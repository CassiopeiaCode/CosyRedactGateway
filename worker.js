// Copyright 2026 CassiopeiaCode
// SPDX-License-Identifier: Apache-2.0
// Cosy Redact Gateway — universal Cloudflare Worker / Deno module.
// Runtime dependencies: none. Requires Web Fetch, Web Streams, and Web Crypto APIs.

const ALL_FLAG_LETTERS = "HPSIBEGM";
const FLAG_NAMES = Object.freeze({
  H: "highEntropy",
  P: "phone",
  S: "secret",
  I: "identity",
  B: "bank",
  E: "email",
  G: "gitleaks",
  M: "manual",
});

export const REDACT_NOTICE =
  "Sensitive values are redacted before forwarding, including messages, tool inputs, and tool results. " +
  "You may see {{Redact:sha256}} placeholders; treat them as opaque and preserve them exactly. " +
  "Sensitive values you read appear as placeholders, and placeholders you emit in text or tool calls are restored to the original secrets.";

const TOKEN_PREFIX = "{{Redact:";
const TOKEN_SUFFIX = "}}";
const TOKEN_RE = /\{\{Redact:[a-f0-9]{64}\}\}/g;
const TOKEN_FULL_RE = /^\{\{Redact:[a-f0-9]{64}\}\}$/;
const TOKEN_LENGTH = TOKEN_PREFIX.length + 64 + TOKEN_SUFFIX.length;
const DEFAULT_MAX_BODY_BYTES = 16 * 1024 * 1024;
const DEFAULT_MAX_REDACTIONS = 16384;
const textEncoder = new TextEncoder();

function randomSalt() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

// One salt per runtime/isolate startup, initialized lazily inside request handling.
let runtimeSalt = null;
function getRuntimeSalt() {
  if (runtimeSalt === null) runtimeSalt = randomSalt();
  return runtimeSalt;
}

export function parseFlags(raw) {
  const upper = (raw || "").toUpperCase();
  const letters = upper || ALL_FLAG_LETTERS;
  const unknown = [...letters].filter((c) => !(c in FLAG_NAMES));
  if (unknown.length) throw new Error(`Unknown flag(s): ${[...new Set(unknown)].join("")}`);
  const out = { highEntropy:false, phone:false, secret:false, identity:false, bank:false, email:false, gitleaks:false, manual:false };
  for (const c of letters) out[FLAG_NAMES[c]] = true;
  return out;
}

function isForbiddenUpstreamHost(hostname) {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (host === "localhost" || host.endsWith(".localhost")) return true;
  if (host === "::1" || host === "::" || /^0*:0*:0*:0*:0*:0*:0*:0*1$/.test(host)) return true;
  if (/^fe80:/i.test(host) || /^f[cd][0-9a-f]{2}:/i.test(host)) return true;
  const mapped = host.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
  const v4 = (mapped ? mapped[1] : host).match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (v4) {
    const [a, b] = v4.slice(1).map(Number);
    if (a === 10 || a === 127 || a === 0) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
  }
  return false;
}

export function parseProxyTarget(requestUrl, { blockPrivate = true } = {}) {
  const u = new URL(requestUrl);
  const routed = u.pathname + u.search;
  const dollar = routed.indexOf("$");
  if (dollar < 0) return null;
  const flagText = routed.slice(1, dollar);
  const upstreamText = routed.slice(dollar + 1);
  if (!upstreamText) throw new Error("Missing upstream URL after '$'");
  const upstream = new URL(upstreamText);
  if (upstream.protocol !== "https:" && upstream.protocol !== "http:") throw new Error("Only http/https upstream URLs are supported");
  if (upstream.username || upstream.password) throw new Error("Upstream URLs containing userinfo are not supported");
  if (blockPrivate && isForbiddenUpstreamHost(upstream.hostname)) throw new Error("Upstream URLs targeting private, loopback, or link-local addresses are not supported");
  return { flags: parseFlags(flagText), flagText: flagText || ALL_FLAG_LETTERS, upstream };
}

export function tokenizeBlocks(text) {
  const blocks = [];
  const re = /[A-Za-z0-9]+/g;
  let m;
  while ((m = re.exec(text))) blocks.push({ value:m[0], start:m.index, end:m.index + m[0].length });
  return blocks;
}

const ENTROPY_THRESHOLDS = [[9,5.448902],[10,5.391602],[11,5.367202],[12,5.306902],[13,5.281402],[16,5.204802],[20,5.086102],[24,5.008202],[32,4.915602],[40,4.857602],[48,4.791102],[56,4.752602],[64,4.730102],[80,4.679802],[96,4.649702],[112,4.619702],[128,4.590902]];
const BIGRAM_COST = {"^":{"a":3.864928,"b":4.341248,"c":3.528992,"d":4.284291,"e":4.696685,"f":4.912851,"g":4.966916,"h":4.833851,"i":4.714267,"j":7.035972,"k":6.55977,"l":5.143802,"m":4.234145,"n":4.829479,"o":4.871561,"p":3.463494,"q":7.620794,"r":4.398027,"s":3.264297,"t":4.297062,"u":4.092077,"v":6.113438,"w":5.770025,"x":9.219252,"y":8.20975,"z":8.129921,"0":19.367728,"1":19.367728,"2":14.975411,"3":14.975411,"4":19.367728,"5":19.367728,"6":19.367728,"7":19.367728,"8":19.367728,"9":19.367728,"$":19.367728},"a":{"a":10.11843,"b":4.501415,"c":4.034515,"d":4.840982,"e":5.746943,"f":7.091539,"g":5.051675,"h":7.851064,"i":5.450971,"j":10.031842,"k":6.712438,"l":2.90034,"m":4.699378,"n":2.92476,"o":9.720599,"p":4.834707,"q":9.887986,"r":3.211564,"s":3.99703,"t":2.749946,"u":5.788937,"v":6.519407,"w":7.305985,"x":7.813257,"y":6.679698,"z":7.720035,"0":19.040271,"1":13.109534,"2":11.709354,"3":14.647954,"4":19.040271,"5":14.647954,"6":19.040271,"7":19.040271,"8":19.040271,"9":19.040271,"$":4.326079},"b":{"a":2.69852,"b":5.361864,"c":7.041481,"d":7.078218,"e":2.974334,"f":8.669962,"g":9.483703,"h":8.552525,"i":2.905571,"j":6.980149,"k":9.944255,"l":2.38698,"m":7.840205,"n":8.552525,"o":3.282142,"p":7.751225,"q":10.275461,"r":3.511838,"s":5.337368,"t":6.909233,"u":3.821859,"v":8.877982,"w":8.854618,"x":13.644695,"y":6.42768,"z":11.03326,"0":16.81462,"1":16.81462,"2":11.457068,"3":12.422303,"4":16.81462,"5":16.81462,"6":10.156409,"7":16.81462,"8":16.81462,"9":16.81462,"$":6.090959},"c":{"a":2.78092,"b":12.200166,"c":6.085277,"d":10.417473,"e":3.363367,"f":10.122807,"g":12.105529,"h":2.948022,"i":3.851663,"j":13.690492,"k":4.525944,"l":4.773475,"m":9.747419,"n":9.137365,"o":2.595001,"p":10.37545,"q":9.729662,"r":4.234284,"s":7.045949,"t":3.702551,"u":4.367812,"v":12.656544,"w":10.825421,"x":16.497847,"y":5.53471,"z":11.974285,"0":18.082809,"1":13.690492,"2":13.690492,"3":12.725257,"4":18.082809,"5":13.690492,"6":18.082809,"7":18.082809,"8":13.690492,"9":18.082809,"$":3.602839},"d":{"a":3.610456,"b":7.612455,"c":8.213508,"d":5.634058,"e":2.29781,"f":7.699518,"g":6.464747,"h":7.627899,"i":2.622853,"j":8.045094,"k":10.956311,"l":5.084725,"m":6.465903,"n":6.516508,"o":3.923483,"p":8.972649,"q":12.393175,"r":4.666084,"s":5.313235,"t":8.256871,"u":5.186815,"v":8.301578,"w":7.691382,"x":13.227165,"y":6.197577,"z":11.728359,"0":13.358409,"1":11.819989,"2":11.410877,"3":17.750727,"4":13.358409,"5":12.393175,"6":17.750727,"7":17.750727,"8":17.750727,"9":17.750727,"$":1.942341},"e":{"a":4.679497,"b":7.025742,"c":4.758296,"d":3.639464,"e":5.73924,"f":6.241768,"g":6.348624,"h":8.047214,"i":6.457275,"j":9.882342,"k":9.050958,"l":4.217786,"m":4.860062,"n":3.362452,"o":6.025347,"p":5.520845,"q":8.084,"r":2.504447,"s":3.07463,"t":4.263903,"u":6.558319,"v":6.747136,"w":6.856607,"x":5.733857,"y":7.494114,"z":9.686604,"0":12.115575,"1":15.054174,"2":14.08894,"3":15.054174,"4":19.446492,"5":19.446492,"6":13.515754,"7":19.446492,"8":19.446492,"9":19.446492,"$":2.775407},"f":{"a":3.635265,"b":10.02602,"c":8.09805,"d":9.259384,"e":3.012761,"f":3.922937,"g":9.989026,"h":9.259384,"i":2.165861,"j":12.592367,"k":9.153256,"l":3.449475,"m":8.70035,"n":8.332805,"o":2.732355,"p":9.259384,"q":11.900489,"r":3.95101,"s":6.676258,"t":5.003364,"u":3.577917,"v":11.769245,"w":10.459917,"x":13.970879,"y":5.55387,"z":13.122882,"0":16.292807,"1":11.900489,"2":10.36207,"3":11.900489,"4":16.292807,"5":16.292807,"6":16.292807,"7":16.292807,"8":11.900489,"9":16.292807,"$":4.911805},"g":{"a":3.604435,"b":8.75025,"c":9.812177,"d":7.716302,"e":2.452107,"f":8.582571,"g":5.354664,"h":4.936271,"i":3.342143,"j":12.706468,"k":11.299292,"l":4.026835,"m":6.585272,"n":4.85907,"o":4.189226,"p":9.762424,"q":15.645067,"r":3.475664,"s":5.595673,"t":7.602496,"u":4.56181,"v":12.275834,"w":8.561145,"x":12.837712,"y":5.547474,"z":11.872478,"0":17.23003,"1":17.23003,"2":11.299292,"3":12.837712,"4":17.23003,"5":17.23003,"6":17.23003,"7":17.23003,"8":17.23003,"9":17.23003,"$":2.16811},"h":{"a":2.65901,"b":8.278382,"c":9.147744,"d":9.253484,"e":2.278164,"f":8.256229,"g":10.035015,"h":9.379513,"i":2.677865,"j":12.537515,"k":10.497987,"l":5.781144,"m":6.53835,"n":6.635084,"o":2.695805,"p":9.078083,"q":10.634191,"r":4.569808,"s":6.699011,"t":5.040033,"u":5.126553,"v":9.17866,"w":7.90654,"x":17.292403,"y":3.599678,"z":12.248008,"0":17.292403,"1":17.292403,"2":12.900085,"3":12.900085,"4":17.292403,"5":17.292403,"6":17.292403,"7":17.292403,"8":17.292403,"9":17.292403,"$":3.825179},"i":{"a":4.025066,"b":6.088786,"c":3.220754,"d":4.40618,"e":4.410616,"f":5.715123,"g":5.356126,"h":9.64576,"i":9.187999,"j":11.284778,"k":7.058419,"l":4.270991,"m":5.093387,"n":2.318803,"o":3.789927,"p":5.495123,"q":9.374925,"r":5.417731,"s":3.157653,"t":3.656803,"u":7.241347,"v":5.236057,"w":11.072408,"x":7.435811,"y":12.056044,"z":5.266719,"0":19.111327,"1":14.719009,"2":19.111327,"3":19.111327,"4":19.111327,"5":19.111327,"6":19.111327,"7":19.111327,"8":19.111327,"9":19.111327,"$":6.609738},"j":{"a":2.058739,"b":11.090509,"c":10.242513,"d":9.711998,"e":2.352417,"f":13.412438,"g":11.827475,"h":9.711998,"i":4.00517,"j":9.711998,"k":10.605083,"l":10.605083,"m":11.090509,"n":8.458241,"o":2.476536,"p":11.090509,"q":13.412438,"r":9.505547,"s":4.171646,"t":11.090509,"u":2.175825,"v":11.827475,"w":11.090509,"x":13.412438,"y":9.505547,"z":13.412438,"0":13.412438,"1":9.02012,"2":9.02012,"3":13.412438,"4":7.4817,"5":13.412438,"6":13.412438,"7":13.412438,"8":13.412438,"9":13.412438,"$":5.585889},"k":{"a":3.716434,"b":5.893791,"c":7.818416,"d":7.30711,"e":1.761122,"f":6.888642,"g":8.446447,"h":6.084718,"i":2.733067,"j":10.248766,"k":7.818416,"l":4.570832,"m":6.233453,"n":5.247667,"o":4.915447,"p":7.681506,"q":14.021356,"r":6.15717,"s":3.971054,"t":6.144839,"u":4.730569,"v":10.05173,"w":6.264244,"x":14.021356,"y":5.499101,"z":13.28439,"0":15.606318,"1":15.606318,"2":11.214001,"3":15.606318,"4":15.606318,"5":15.606318,"6":15.606318,"7":15.606318,"8":15.606318,"9":15.606318,"$":2.905229},"l":{"a":2.972426,"b":7.755079,"c":7.229571,"d":5.60569,"e":2.451954,"f":7.444965,"g":7.774527,"h":9.32606,"i":2.578801,"j":12.76477,"k":7.840074,"l":3.4729,"m":7.194617,"n":7.495414,"o":3.366194,"p":6.962982,"q":12.371106,"r":8.94334,"s":5.973926,"t":5.467989,"u":4.847895,"v":7.452065,"w":9.279848,"x":14.349732,"y":3.424091,"z":11.542378,"0":18.437195,"1":12.506458,"2":12.097345,"3":13.079643,"4":18.437195,"5":18.437195,"6":18.437195,"7":18.437195,"8":18.437195,"9":18.437195,"$":3.474435},"m":{"a":2.460152,"b":4.713677,"c":8.765867,"d":9.253844,"e":2.452203,"f":8.531242,"g":9.712717,"h":10.276351,"i":2.516976,"j":12.034645,"k":10.769055,"l":7.302676,"m":4.946506,"n":6.672608,"o":3.158455,"p":3.832157,"q":14.129803,"r":9.424327,"s":5.660346,"t":8.442029,"u":4.764077,"v":9.895747,"w":8.831011,"x":13.065672,"y":5.39171,"z":11.611954,"0":17.589234,"1":12.231682,"2":11.658497,"3":17.589234,"4":17.589234,"5":17.589234,"6":17.589234,"7":17.589234,"8":17.589234,"9":17.589234,"$":3.419231},"n":{"a":3.794653,"b":7.566803,"c":4.205726,"d":3.96577,"e":3.021994,"f":5.987053,"g":3.12569,"h":7.586144,"i":3.606712,"j":9.027586,"k":6.767102,"l":6.877443,"m":7.237569,"n":6.012994,"o":3.659832,"p":6.546238,"q":9.034212,"r":6.899201,"s":4.018577,"t":3.068095,"u":6.13231,"v":6.896935,"w":8.134756,"x":11.281724,"y":7.096551,"z":9.067803,"0":18.797424,"1":12.866687,"2":11.878561,"3":18.797424,"4":18.797424,"5":18.797424,"6":18.797424,"7":18.797424,"8":18.797424,"9":18.797424,"$":3.254483},"o":{"a":6.092565,"b":5.773364,"c":4.585961,"d":4.836884,"e":6.540338,"f":6.744024,"g":4.672211,"h":8.035532,"i":5.431433,"j":9.856673,"k":6.703825,"l":3.876597,"m":3.901766,"n":2.396056,"o":5.027137,"p":4.142679,"q":9.716767,"r":2.991944,"s":4.044551,"t":4.357265,"u":3.750962,"v":5.35733,"w":5.838969,"x":6.983674,"y":7.996161,"z":8.528295,"0":18.796252,"1":18.796252,"2":18.796252,"3":18.796252,"4":18.796252,"5":18.796252,"6":13.4387,"7":18.796252,"8":14.403935,"9":18.796252,"$":6.144528},"p":{"a":3.101873,"b":8.843607,"c":9.364991,"d":8.385617,"e":2.704618,"f":8.869199,"g":9.040335,"h":2.937615,"i":3.602286,"j":12.815349,"k":9.784587,"l":3.858047,"m":8.567421,"n":7.761938,"o":3.169194,"p":4.977884,"q":14.503405,"r":2.985243,"s":4.928286,"t":4.51267,"u":4.871419,"v":10.415942,"w":9.177475,"x":16.088367,"y":5.98115,"z":16.088367,"0":17.67333,"1":13.281012,"2":11.742592,"3":17.67333,"4":12.315778,"5":17.67333,"6":17.67333,"7":17.67333,"8":17.67333,"9":17.67333,"$":5.055174},"q":{"a":8.463524,"b":13.592807,"c":13.592807,"d":8.948951,"e":10.422882,"f":12.007845,"g":13.592807,"h":13.592807,"i":8.734826,"j":13.592807,"k":13.592807,"l":4.455816,"m":9.20049,"n":8.166543,"o":8.734826,"p":8.100954,"q":10.785452,"r":10.422882,"s":7.978098,"t":9.685917,"u":0.143014,"v":11.270879,"w":11.270879,"x":13.592807,"y":13.592807,"z":13.592807,"0":13.592807,"1":13.592807,"2":13.592807,"3":13.592807,"4":13.592807,"5":13.592807,"6":13.592807,"7":13.592807,"8":13.592807,"9":13.592807,"$":5.598454},"r":{"a":2.820541,"b":6.441063,"c":5.426071,"d":5.396283,"e":2.581089,"f":7.105998,"g":6.273584,"h":7.06274,"i":2.890009,"j":10.489945,"k":7.121581,"l":6.303387,"m":5.062635,"n":5.871479,"o":3.086302,"p":6.271169,"q":10.661556,"r":5.260707,"s":4.369873,"t":4.857187,"u":5.435507,"v":7.084631,"w":8.094421,"x":12.983484,"y":5.019625,"z":11.238946,"0":18.816374,"1":14.424057,"2":12.885637,"3":14.424057,"4":12.476524,"5":14.424057,"6":12.476524,"7":18.816374,"8":18.816374,"9":18.816374,"$":3.375992},"s":{"a":4.816057,"b":8.950989,"c":4.759648,"d":9.367587,"e":3.372311,"f":7.99936,"g":8.80289,"h":4.570454,"i":3.769714,"j":10.990517,"k":7.135856,"l":6.008867,"m":5.218749,"n":6.611081,"o":4.871991,"p":4.851102,"q":7.689905,"r":8.439069,"s":3.62334,"t":2.84373,"u":4.62369,"v":10.052754,"w":7.126138,"x":13.446746,"y":6.382496,"z":12.296503,"0":18.804298,"1":13.446746,"2":12.873561,"3":14.411981,"4":18.804298,"5":18.804298,"6":18.804298,"7":18.804298,"8":18.804298,"9":18.804298,"$":1.798224},"t":{"a":3.499114,"b":8.705608,"c":6.661504,"d":8.366011,"e":2.356938,"f":7.407116,"g":8.724881,"h":3.911746,"i":2.311159,"j":11.67182,"k":11.51023,"l":6.108164,"m":7.520418,"n":8.273915,"o":3.498004,"p":7.91812,"q":12.24084,"r":3.502971,"s":5.207175,"t":5.224216,"u":5.097247,"v":9.862939,"w":7.602066,"x":11.954219,"y":4.971688,"z":9.005484,"0":18.748635,"1":13.391083,"2":12.817898,"3":12.408785,"4":13.391083,"5":18.748635,"6":12.817898,"7":18.748635,"8":14.356318,"9":18.748635,"$":3.381664},"u":{"a":4.970181,"b":4.61063,"c":4.965149,"d":5.282399,"e":4.983817,"f":7.109508,"g":5.819187,"h":10.46514,"i":4.970569,"j":10.888947,"k":8.08831,"l":3.243626,"m":3.923914,"n":2.288098,"o":6.972704,"p":4.448163,"q":11.854182,"r":3.186085,"s":2.798684,"t":3.718941,"u":9.273041,"v":8.305941,"w":12.216752,"x":8.467327,"y":9.992258,"z":9.046827,"0":17.831462,"1":17.831462,"2":17.831462,"3":17.831462,"4":17.831462,"5":17.831462,"6":17.831462,"7":17.831462,"8":17.831462,"9":17.831462,"$":7.483841},"v":{"a":2.509167,"b":14.32575,"c":10.78143,"d":11.82325,"e":0.942451,"f":9.570863,"g":9.340857,"h":14.32575,"i":2.337184,"j":15.910713,"k":12.740788,"l":10.956517,"m":11.266857,"n":10.625311,"o":3.867344,"p":11.266857,"q":15.910713,"r":8.288661,"s":8.750842,"t":10.78143,"u":6.437007,"v":9.802189,"w":13.588785,"x":15.910713,"y":8.135926,"z":13.588785,"0":15.910713,"1":15.910713,"2":10.553161,"3":15.910713,"4":11.518396,"5":15.910713,"6":15.910713,"7":15.910713,"8":15.910713,"9":15.910713,"$":6.959428},"w":{"a":2.273476,"b":6.888889,"c":8.349277,"d":6.300104,"e":2.847629,"f":7.094162,"g":8.652893,"h":4.145242,"i":2.623743,"j":11.987878,"k":5.635132,"l":5.33487,"m":7.333567,"n":4.754694,"o":2.844378,"p":7.854852,"q":10.021045,"r":4.490933,"s":5.126509,"t":7.452956,"u":7.810685,"v":10.923747,"w":7.979704,"x":15.447309,"y":7.397461,"z":10.402915,"0":6.729633,"1":15.447309,"2":15.447309,"3":10.089757,"4":15.447309,"5":15.447309,"6":15.447309,"7":15.447309,"8":15.447309,"9":15.447309,"$":3.974111},"x":{"a":3.731236,"b":8.441523,"c":3.992007,"d":7.355223,"e":3.540574,"f":7.471476,"g":9.076759,"h":6.127522,"i":2.178849,"j":10.23903,"k":12.30942,"l":7.053919,"m":6.730481,"n":8.60898,"o":4.294841,"p":3.358135,"q":10.23903,"r":8.291498,"s":6.980296,"t":2.766001,"u":5.757903,"v":6.767161,"w":8.291498,"x":8.748705,"y":4.146525,"z":13.046385,"0":10.23903,"1":10.23903,"2":14.631348,"3":10.23903,"4":14.631348,"5":14.631348,"6":14.631348,"7":14.631348,"8":14.631348,"9":14.631348,"$":3.26776},"y":{"a":5.180794,"b":7.27068,"c":4.878789,"d":5.522112,"e":5.16822,"f":7.245805,"g":6.244925,"h":8.484733,"i":5.658496,"j":12.675597,"k":9.423679,"l":4.264198,"m":4.854411,"n":4.952341,"o":5.46974,"p":4.062244,"q":11.969328,"r":5.145859,"s":4.207777,"t":4.833743,"u":8.24053,"v":9.455919,"w":7.640436,"x":8.597095,"y":11.195604,"z":8.579229,"0":12.531207,"1":12.531207,"2":11.565973,"3":9.592608,"4":16.923525,"5":16.923525,"6":16.923525,"7":16.923525,"8":16.923525,"9":16.923525,"$":0.994151},"z":{"a":2.682292,"b":9.619108,"c":10.57604,"d":9.3781,"e":1.207276,"f":9.237238,"g":10.415575,"h":10.57604,"i":2.77895,"j":12.341574,"k":10.019646,"l":5.666323,"m":7.674818,"n":8.780859,"o":3.026425,"p":9.805522,"q":11.856148,"r":8.780859,"s":8.554978,"t":10.271185,"u":6.836954,"v":10.756612,"w":9.805522,"x":14.663503,"y":4.971759,"z":4.851325,"0":14.663503,"1":14.663503,"2":9.305951,"3":14.663503,"4":14.663503,"5":14.663503,"6":14.663503,"7":14.663503,"8":14.663503,"9":14.663503,"$":5.496084},"0":{"a":10.340963,"b":10.340963,"c":10.340963,"d":10.340963,"e":10.340963,"f":10.340963,"g":10.340963,"h":10.340963,"i":10.340963,"j":10.340963,"k":10.340963,"l":10.340963,"m":10.340963,"n":5.948645,"o":10.340963,"p":10.340963,"q":10.340963,"r":10.340963,"s":10.340963,"t":10.340963,"u":10.340963,"v":5.948645,"w":5.948645,"x":10.340963,"y":10.340963,"z":10.340963,"0":2.014533,"1":2.313057,"2":3.010046,"3":4.410225,"4":3.682751,"5":4.983411,"6":4.983411,"7":10.340963,"8":5.948645,"9":4.983411,"$":3.010046},"1":{"a":10.072803,"b":10.072803,"c":10.072803,"d":10.072803,"e":10.072803,"f":4.142065,"g":10.072803,"h":10.072803,"i":5.680485,"j":10.072803,"k":10.072803,"l":10.072803,"m":10.072803,"n":10.072803,"o":10.072803,"p":5.680485,"q":10.072803,"r":5.680485,"s":10.072803,"t":10.072803,"u":10.072803,"v":10.072803,"w":5.680485,"x":10.072803,"y":10.072803,"z":10.072803,"0":4.142065,"1":4.142065,"2":3.732953,"3":4.715251,"4":4.715251,"5":5.680485,"6":3.732953,"7":10.072803,"8":4.715251,"9":5.680485,"$":1.22418},"2":{"a":6.31935,"b":10.711667,"c":10.711667,"d":5.354115,"e":6.31935,"f":5.354115,"g":10.711667,"h":10.711667,"i":6.31935,"j":10.711667,"k":10.711667,"l":10.711667,"m":4.371817,"n":5.354115,"o":10.711667,"p":4.78093,"q":10.711667,"r":10.711667,"s":6.31935,"t":10.711667,"u":10.711667,"v":10.711667,"w":10.711667,"x":10.711667,"y":10.711667,"z":10.711667,"0":5.354115,"1":6.31935,"2":4.371817,"3":5.354115,"4":4.78093,"5":4.371817,"6":10.711667,"7":10.711667,"8":6.31935,"9":10.711667,"$":0.803274},"3":{"a":9.638436,"b":9.638436,"c":4.280884,"d":2.498885,"e":9.638436,"f":9.638436,"g":9.638436,"h":9.638436,"i":9.638436,"j":9.638436,"k":9.638436,"l":9.638436,"m":9.638436,"n":9.638436,"o":9.638436,"p":9.638436,"q":9.638436,"r":9.638436,"s":9.638436,"t":9.638436,"u":9.638436,"v":9.638436,"w":9.638436,"x":9.638436,"y":9.638436,"z":9.638436,"0":9.638436,"1":2.980224,"2":2.980224,"3":4.280884,"4":9.638436,"5":9.638436,"6":4.280884,"7":9.638436,"8":4.280884,"9":3.707699,"$":1.987384},"4":{"a":9.638436,"b":9.638436,"c":9.638436,"d":5.246118,"e":5.246118,"f":5.246118,"g":9.638436,"h":9.638436,"i":9.638436,"j":9.638436,"k":9.638436,"l":5.246118,"m":9.638436,"n":9.638436,"o":9.638436,"p":9.638436,"q":9.638436,"r":9.638436,"s":5.246118,"t":5.246118,"u":9.638436,"v":9.638436,"w":9.638436,"x":9.638436,"y":9.638436,"z":9.638436,"0":2.719573,"1":9.638436,"2":9.638436,"3":9.638436,"4":5.246118,"5":9.638436,"6":5.246118,"7":9.638436,"8":9.638436,"9":9.638436,"$":0.728543},"5":{"a":8.214319,"b":3.822002,"c":8.214319,"d":8.214319,"e":8.214319,"f":8.214319,"g":8.214319,"h":8.214319,"i":8.214319,"j":8.214319,"k":8.214319,"l":8.214319,"m":8.214319,"n":8.214319,"o":8.214319,"p":3.822002,"q":8.214319,"r":8.214319,"s":8.214319,"t":8.214319,"u":8.214319,"v":8.214319,"w":8.214319,"x":8.214319,"y":8.214319,"z":8.214319,"0":2.856767,"1":3.822002,"2":8.214319,"3":3.822002,"4":8.214319,"5":8.214319,"6":2.856767,"7":8.214319,"8":8.214319,"9":8.214319,"$":1.556108},"6":{"a":9.31515,"b":9.31515,"c":9.31515,"d":9.31515,"e":9.31515,"f":9.31515,"g":9.31515,"h":9.31515,"i":9.31515,"j":9.31515,"k":9.31515,"l":9.31515,"m":9.31515,"n":9.31515,"o":9.31515,"p":4.922832,"q":9.31515,"r":9.31515,"s":9.31515,"t":9.31515,"u":9.31515,"v":9.31515,"w":9.31515,"x":9.31515,"y":9.31515,"z":9.31515,"0":3.957598,"1":4.922832,"2":3.957598,"3":9.31515,"4":1.287244,"5":9.31515,"6":9.31515,"7":9.31515,"8":9.31515,"9":9.31515,"$":1.527247},"7":{"a":5.209453,"b":5.209453,"c":5.209453,"d":5.209453,"e":5.209453,"f":5.209453,"g":5.209453,"h":5.209453,"i":5.209453,"j":5.209453,"k":5.209453,"l":5.209453,"m":5.209453,"n":5.209453,"o":5.209453,"p":5.209453,"q":5.209453,"r":5.209453,"s":5.209453,"t":5.209453,"u":5.209453,"v":5.209453,"w":5.209453,"x":5.209453,"y":5.209453,"z":5.209453,"0":5.209453,"1":5.209453,"2":5.209453,"3":5.209453,"4":5.209453,"5":5.209453,"6":5.209453,"7":5.209453,"8":5.209453,"9":5.209453,"$":5.209453},"8":{"a":8.005625,"b":8.005625,"c":8.005625,"d":8.005625,"e":8.005625,"f":8.005625,"g":8.005625,"h":8.005625,"i":8.005625,"j":8.005625,"k":8.005625,"l":8.005625,"m":8.005625,"n":3.613307,"o":8.005625,"p":8.005625,"q":8.005625,"r":8.005625,"s":8.005625,"t":8.005625,"u":8.005625,"v":8.005625,"w":8.005625,"x":8.005625,"y":8.005625,"z":8.005625,"0":8.005625,"1":8.005625,"2":3.613307,"3":8.005625,"4":3.613307,"5":3.613307,"6":2.648073,"7":8.005625,"8":8.005625,"9":8.005625,"$":1.347413},"9":{"a":7.294621,"b":7.294621,"c":7.294621,"d":7.294621,"e":7.294621,"f":7.294621,"g":7.294621,"h":7.294621,"i":7.294621,"j":7.294621,"k":7.294621,"l":7.294621,"m":7.294621,"n":7.294621,"o":7.294621,"p":7.294621,"q":7.294621,"r":7.294621,"s":7.294621,"t":7.294621,"u":7.294621,"v":7.294621,"w":7.294621,"x":7.294621,"y":7.294621,"z":7.294621,"0":7.294621,"1":2.902303,"2":7.294621,"3":7.294621,"4":7.294621,"5":7.294621,"6":7.294621,"7":7.294621,"8":2.902303,"9":7.294621,"$":0.954771}};

export function entropyThreshold(length) {
  if (length <= 8) return Infinity;
  if (length >= ENTROPY_THRESHOLDS[ENTROPY_THRESHOLDS.length - 1][0]) return ENTROPY_THRESHOLDS[ENTROPY_THRESHOLDS.length - 1][1];
  for (let i = 0; i < ENTROPY_THRESHOLDS.length - 1; i++) {
    const [l1, h1] = ENTROPY_THRESHOLDS[i];
    const [l2, h2] = ENTROPY_THRESHOLDS[i + 1];
    if (length >= l1 && length <= l2) {
      const t = (length - l1) / (l2 - l1);
      return h1 + (h2 - h1) * t;
    }
  }
  return ENTROPY_THRESHOLDS[0][1];
}

function shannonEntropy(s) {
  const counts = new Map();
  for (const c of s) counts.set(c, (counts.get(c) || 0) + 1);
  let h = 0;
  for (const n of counts.values()) { const p = n / s.length; h -= p * Math.log2(p); }
  return h;
}

export function entropyScore(block) {
  if (block.length <= 8 || !/^[A-Za-z0-9]+$/.test(block) || /^\d+$/.test(block)) return 0;
  const s = block.toLowerCase();
  let prev = "^", bits = 0;
  for (const ch of s) {
    const row = BIGRAM_COST[prev] || BIGRAM_COST["^"];
    bits += row[ch] ?? 12;
    prev = ch;
  }
  bits += (BIGRAM_COST[prev] || BIGRAM_COST["^"])["$"] ?? 12;
  return bits / (s.length + 1);
}

export function isHighEntropyBlock(block) {
  if (block.length <= 8 || /^\d+$/.test(block)) return false;
  // Cross-entropy alone can rate repeated odd strings highly. Require actual symbol diversity too.
  if (shannonEntropy(block.toLowerCase()) < Math.min(2.5, Math.log2(block.length) * 0.72)) return false;
  return entropyScore(block) > entropyThreshold(block.length);
}

function luhnValid(digits) {
  let sum = 0, doubleIt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = digits.charCodeAt(i) - 48;
    if (doubleIt) { n *= 2; if (n > 9) n -= 9; }
    sum += n; doubleIt = !doubleIt;
  }
  return sum % 10 === 0;
}

function chinaIdValid(id) {
  if (!/^\d{17}[0-9Xx]$/.test(id)) return false;
  const weights = [7,9,10,5,8,4,2,1,6,3,7,9,10,5,8,4,2];
  const checks = "10X98765432";
  let sum = 0;
  for (let i = 0; i < 17; i++) sum += Number(id[i]) * weights[i];
  return checks[sum % 11] === id[17].toUpperCase();
}

// Portable execution layer for the current upstream Gitleaks default rule style.
// Upstream uses Go/RE2 + TOML metadata. In a single Web-API-only Worker we execute
// JavaScript-safe equivalents and preserve the important rule semantics: keywords,
// secretGroup extraction, Shannon entropy thresholds, regex allowlists, and stopwords.
// File-path-only rules have no meaningful path in an LLM JSON body and are therefore
// not included. See docs/GITLEAKS-COMPAT.md.
function regexEscape(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function glRule(id, regex, options = {}) {
  return {
    id,
    regex,
    secretGroup: options.secretGroup || 0,
    entropy: options.entropy || 0,
    keywords: (options.keywords || []).map((x) => x.toLowerCase()),
    allowRegexes: options.allowRegexes || [],
    stopwords: (options.stopwords || []).map((x) => x.toLowerCase()),
  };
}

function assignmentRule(id, names, valueSource, options = {}) {
  const keys = Array.isArray(names) ? names : [names];
  const keySource = options.keySource || keys.map(regexEscape).join("|");
  const regex = new RegExp(
    String.raw`[\w.-]{0,50}?(?:${keySource})(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(${valueSource})(?:[\x60'"\s;]|\\[nr]|$)`,
    "gi",
  );
  return glRule(id, regex, { ...options, secretGroup: 1, keywords: options.keywords || keys });
}

const GITLEAK_DIRECT_RULES = [
  glRule("1password-secret-key", /\b(A3-[A-Z0-9]{6}-(?:(?:[A-Z0-9]{11})|(?:[A-Z0-9]{6}-[A-Z0-9]{5}))-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5})\b/g, { secretGroup:1, entropy:3.8, keywords:["a3-"] }),
  glRule("1password-service-account-token", /(ops_eyJ[A-Za-z0-9+/]{250,}={0,3})/g, { secretGroup:1, entropy:4, keywords:["ops_"] }),
  glRule("age-secret-key", /(AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58})/g, { secretGroup:1, keywords:["age-secret-key-1"] }),
  glRule("airtable-personal-access-token", /\b(pat[A-Za-z0-9]{14}\.[a-f0-9]{64})\b/g, { secretGroup:1, keywords:["pat"] }),
  glRule("alibaba-access-key-id", /\b(LTAI[a-z0-9]{20})(?:[\x60'"\s;]|\\[nr]|$)/gi, { secretGroup:1, entropy:2, keywords:["ltai"] }),
  glRule("anthropic-admin-api-key", /\b(sk-ant-admin01-[A-Za-z0-9_-]{93}AA)(?:[\x60'"\s;]|\\[nr]|$)/g, { secretGroup:1, keywords:["sk-ant-admin01"] }),
  glRule("anthropic-api-key", /\b(sk-ant-api03-[A-Za-z0-9_-]{93}AA)(?:[\x60'"\s;]|\\[nr]|$)/g, { secretGroup:1, keywords:["sk-ant-api03"] }),
  glRule("artifactory-api-key", /\b(AKCp[A-Za-z0-9]{69})\b/g, { secretGroup:1, entropy:4.5, keywords:["akcp"] }),
  glRule("artifactory-reference-token", /\b(cmVmd[A-Za-z0-9]{59})\b/g, { secretGroup:1, entropy:4.5, keywords:["cmvmd"] }),
  glRule("aws-access-token", /\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b/g, { secretGroup:1, entropy:3, keywords:["a3t","akia","asia","abia","acca"], allowRegexes:[/.+EXAMPLE$/] }),
  glRule("aws-bedrock-long-lived", /\b(ABSK[A-Za-z0-9+/]{109,269}={0,2})(?:[\x60'"\s;]|\\[nr]|$)/g, { secretGroup:1, entropy:3, keywords:["absk"] }),
  glRule("aws-bedrock-short-lived", /(bedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29t)/g, { secretGroup:1, entropy:3, keywords:["bedrock-api-key-"] }),
  glRule("azure-ad-client-secret", /(?:^|[\\'"`\s>=:(,)])([A-Za-z0-9_~.]{3}\dQ~[A-Za-z0-9_~.-]{31,34})(?:$|[\\'"`\s<),])/g, { secretGroup:1, entropy:3, keywords:["q~"] }),
  glRule("clickhouse-cloud-api-secret-key", /\b(4b1d[A-Za-z0-9]{38})\b/g, { secretGroup:1, entropy:3, keywords:["4b1d"] }),
  glRule("clojars-api-token", /(CLOJARS_[A-Za-z0-9]{60})/gi, { secretGroup:1, entropy:2, keywords:["clojars_"] }),
  glRule("databricks-api-token", /\b(dapi[a-f0-9]{32}(?:-\d)?)(?:[\x60'"\s;]|\\[nr]|$)/gi, { secretGroup:1, entropy:3, keywords:["dapi"] }),
  glRule("defined-networking-api-token", /\b(dnkey-[A-Za-z0-9=_-]{26}-[A-Za-z0-9=_-]{52})\b/gi, { secretGroup:1, keywords:["dnkey"] }),
  glRule("digitalocean-access-token", /\b(doo_v1_[a-f0-9]{64})(?:[\x60'"\s;]|\\[nr]|$)/gi, { secretGroup:1, entropy:3, keywords:["doo_v1_"] }),
  glRule("digitalocean-pat", /\b(dop_v1_[a-f0-9]{64})(?:[\x60'"\s;]|\\[nr]|$)/gi, { secretGroup:1, entropy:3, keywords:["dop_v1_"] }),
  glRule("digitalocean-refresh-token", /\b(dor_v1_[a-f0-9]{64})(?:[\x60'"\s;]|\\[nr]|$)/gi, { secretGroup:1, keywords:["dor_v1_"] }),
  glRule("doppler-api-token", /(dp\.pt\.[A-Za-z0-9]{43})/gi, { secretGroup:1, entropy:2, keywords:["dp.pt."] }),
  glRule("dropbox-short-lived-api-token", /\b(sl\.[A-Za-z0-9=_-]{135})\b/gi, { secretGroup:1, keywords:["sl."] }),
  glRule("flutterwave-encryption-key", /(FLWSECK_TEST-[A-H0-9]{12})/gi, { secretGroup:1, entropy:2, keywords:["flwseck_test"] }),
  glRule("flutterwave-public-key", /(FLWPUBK_TEST-[A-H0-9]{32}-X)/gi, { secretGroup:1, entropy:2, keywords:["flwpubk_test"] }),
  glRule("flutterwave-secret-key", /(FLWSECK_TEST-[A-H0-9]{32}-X)/gi, { secretGroup:1, entropy:2, keywords:["flwseck_test"] }),
  glRule("flyio-access-token", /\b((?:fo1_[\w-]{43}|fm1[ar]_[A-Za-z0-9+/]{100,}={0,3}|fm2_[A-Za-z0-9+/]{100,}={0,3}))(?:[\x60'"\s;]|\\[nr]|$)/g, { secretGroup:1, entropy:4, keywords:["fo1_","fm1","fm2_"] }),
  glRule("frameio-api-token", /(fio-u-[A-Za-z0-9\-_=]{64})/gi, { secretGroup:1, keywords:["fio-u-"] }),
  glRule("gcp-api-key", /\b(AIza[\w-]{35})(?:[\x60'"\s;]|\\[nr]|$)/g, { secretGroup:1, entropy:4, keywords:["aiza"], allowRegexes:[/^AIzaSyabcdefghijklmnopqrstuvwxyz1234567$/] }),
  glRule("github-classic-token", /\b(gh[pousr]_[A-Za-z0-9]{36,255})\b/g, { secretGroup:1, keywords:["ghp_","gho_","ghu_","ghs_","ghr_"] }),
  glRule("github-fine-grained-pat", /\b(github_pat_[A-Za-z0-9_]{70,255})\b/g, { secretGroup:1, keywords:["github_pat_"] }),
  glRule("gitlab-deploy-token", /(gldt-[0-9A-Za-z_-]{20})/g, { secretGroup:1, entropy:3, keywords:["gldt-"] }),
  glRule("gitlab-feature-flag-client-token", /(glffct-[0-9A-Za-z_-]{20})/g, { secretGroup:1, entropy:3, keywords:["glffct-"] }),
  glRule("gitlab-feed-token", /(glft-[0-9A-Za-z_-]{20})/g, { secretGroup:1, entropy:3, keywords:["glft-"] }),
  glRule("gitlab-incoming-mail-token", /(glimt-[0-9A-Za-z_-]{25})/g, { secretGroup:1, entropy:3, keywords:["glimt-"] }),
  glRule("gitlab-kubernetes-agent-token", /(glagent-[0-9A-Za-z_-]{50})/g, { secretGroup:1, entropy:3, keywords:["glagent-"] }),
  glRule("gitlab-oauth-app-secret", /(gloas-[0-9A-Za-z_-]{64})/g, { secretGroup:1, entropy:3, keywords:["gloas-"] }),
  glRule("gitlab-pat", /(glpat-[\w-]{20})/g, { secretGroup:1, entropy:3, keywords:["glpat-"] }),
  glRule("gitlab-pat-routable", /\b(glpat-[0-9A-Za-z_-]{27,300}\.[0-9a-z]{9})\b/g, { secretGroup:1, entropy:4, keywords:["glpat-"] }),
  glRule("gitlab-ptt", /(glptt-[0-9a-f]{40})/g, { secretGroup:1, entropy:3, keywords:["glptt-"] }),
  glRule("gitlab-rrt", /(GR1348941[\w-]{20})/g, { secretGroup:1, entropy:3, keywords:["gr1348941"] }),
  glRule("gitlab-scim-token", /(glsoat-[0-9A-Za-z_-]{20})/g, { secretGroup:1, entropy:3, keywords:["glsoat-"] }),
  glRule("gitlab-session-cookie", /(_gitlab_session=[0-9a-z]{32})/g, { secretGroup:1, entropy:3, keywords:["_gitlab_session="] }),
  glRule("grafana-api-key", /\b(eyJrIjoi[A-Za-z0-9]{70,400}={0,3})(?:[\x60'"\s;]|\\[nr]|$)/gi, { secretGroup:1, entropy:3, keywords:["eyjrijoi"] }),
  glRule("grafana-cloud-api-token", /\b(glc_[A-Za-z0-9+/]{32,400}={0,3})(?:[\x60'"\s;]|\\[nr]|$)/gi, { secretGroup:1, entropy:3, keywords:["glc_"] }),
  glRule("grafana-service-account-token", /\b(glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8})(?:[\x60'"\s;]|\\[nr]|$)/gi, { secretGroup:1, entropy:3, keywords:["glsa_"] }),
  glRule("harness-api-key", /\b((?:pat|sat)\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9]{24}\.[A-Za-z0-9]{20})\b/g, { secretGroup:1, keywords:["pat.","sat."] }),
  glRule("hashicorp-tf-api-token", /\b([a-z0-9]{14}\.atlasv1\.[a-z0-9\-_=]{60,70})\b/gi, { secretGroup:1, entropy:3.5, keywords:["atlasv1"] }),
  glRule("heroku-api-key-v2", /\b(HRKU-AA[0-9A-Za-z_-]{58})(?:[\x60'"\s;]|\\[nr]|$)/g, { secretGroup:1, entropy:4, keywords:["hrku-aa"] }),
  glRule("huggingface-access-token", /\b(hf_[a-z]{34})(?:[\x60'"\s;]|\\[nr]|$)/gi, { secretGroup:1, entropy:2, keywords:["hf_"] }),
  glRule("huggingface-organization-api-token", /\b(api_org_[a-z]{34})(?:[\x60'"\s;]|\\[nr]|$)/gi, { secretGroup:1, entropy:2, keywords:["api_org_"] }),
  glRule("infracost-api-token", /\b(ico-[A-Za-z0-9]{32})(?:[\x60'"\s;]|\\[nr]|$)/g, { secretGroup:1, entropy:3, keywords:["ico-"] }),
  glRule("intra42-client-secret", /\b(s-s4t2(?:ud|af)-[a-f0-9]{64})(?:[\x60'"\s;]|\\[nr]|$)/gi, { secretGroup:1, entropy:3, keywords:["s-s4t2ud-","s-s4t2af-"] }),
  glRule("jwt-compact-broad", /\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,})\b/g, { secretGroup:1, entropy:3 }),
  glRule("linear-api-key", /(lin_api_[A-Za-z0-9]{40})/gi, { secretGroup:1, entropy:2, keywords:["lin_api_"] }),
  glRule("mailgun-private-api-token", /\b(key-[a-f0-9]{32})\b/gi, { secretGroup:1, keywords:["key-"] }),
  glRule("microsoft-teams-webhook", /(https:\/\/[a-z0-9]+\.webhook\.office\.com\/webhookb2\/[a-z0-9]{8}-(?:[a-z0-9]{4}-){3}[a-z0-9]{12}@[a-z0-9]{8}-(?:[a-z0-9]{4}-){3}[a-z0-9]{12}\/IncomingWebhook\/[a-z0-9]{32}\/[a-z0-9]{8}-(?:[a-z0-9]{4}-){3}[a-z0-9]{12})/gi, { secretGroup:1, keywords:["webhook.office.com","incomingwebhook"] }),
  glRule("new-relic-browser-api-token", /\b(NRJS-[a-f0-9]{19})\b/gi, { secretGroup:1, keywords:["nrjs-"] }),
  glRule("new-relic-user-api-key", /\b(NRAK-[a-z0-9]{27})\b/gi, { secretGroup:1, keywords:["nrak"] }),
  glRule("notion-api-token", /\b(ntn_[0-9]{11}[A-Za-z0-9]{35})(?:[\x60'"\s;]|\\[nr]|$)/g, { secretGroup:1, entropy:4, keywords:["ntn_"] }),
  glRule("npm-access-token", /\b(npm_[a-z0-9]{36})(?:[\x60'"\s;]|\\[nr]|$)/gi, { secretGroup:1, entropy:2, keywords:["npm_"] }),
  glRule("openshift-user-token", /\b(sha256~[\w-]{43})(?:[^\w-]|$)/g, { secretGroup:1, entropy:3.5, keywords:["sha256~"] }),
  glRule("openai-api-key", /\b(sk-(?:proj-)?[A-Za-z0-9_-]{20,200})\b/g, { secretGroup:1, entropy:3, keywords:["sk-"] }),
  glRule("perplexity-api-key", /\b(pplx-[A-Za-z0-9]{48})(?:[\x60'"\s;]|\\[nr]|$|\b)/g, { secretGroup:1, entropy:4, keywords:["pplx-"] }),
  glRule("planetscale-api-token", /\b(pscale_tkn_[\w=.-]{32,64})(?:[\x60'"\s;]|\\[nr]|$)/gi, { secretGroup:1, entropy:3, keywords:["pscale_tkn_"] }),
  glRule("planetscale-oauth-token", /\b(pscale_oauth_[\w=.-]{32,64})(?:[\x60'"\s;]|\\[nr]|$)/g, { secretGroup:1, entropy:3, keywords:["pscale_oauth_"] }),
  glRule("planetscale-password", /\b(pscale_pw_[\w=.-]{32,64})(?:[\x60'"\s;]|\\[nr]|$)/gi, { secretGroup:1, entropy:3, keywords:["pscale_pw_"] }),
  glRule("postman-api-token", /\b(PMAK-[a-f0-9]{24}-[a-f0-9]{34})(?:[\x60'"\s;]|\\[nr]|$)/gi, { secretGroup:1, entropy:3, keywords:["pmak-"] }),
  glRule("prefect-api-token", /\b(pnu_[A-Za-z0-9]{36})(?:[\x60'"\s;]|\\[nr]|$)/g, { secretGroup:1, entropy:2, keywords:["pnu_"] }),
  glRule("private-key", /(-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----[\s\S-]{64,}?KEY(?: BLOCK)?-----)/gi, { secretGroup:1, keywords:["-----begin"] }),
  glRule("pulumi-api-token", /\b(pul-[a-f0-9]{40})(?:[\x60'"\s;]|\\[nr]|$)/g, { secretGroup:1, entropy:2, keywords:["pul-"] }),
  glRule("pypi-upload-token", /(pypi-AgEIcHlwaS5vcmc[\w-]{50,1000})/g, { secretGroup:1, entropy:3, keywords:["pypi-ageichlwas5vcmc"] }),
  glRule("readme-api-token", /\b(rdme_[a-z0-9]{70})(?:[\x60'"\s;]|\\[nr]|$)/g, { secretGroup:1, entropy:2, keywords:["rdme_"] }),
  glRule("rubygems-api-token", /\b(rubygems_[a-f0-9]{48})(?:[\x60'"\s;]|\\[nr]|$)/g, { secretGroup:1, entropy:2, keywords:["rubygems_"] }),
  glRule("scalingo-api-token", /\b(tk-us-[\w-]{48})(?:[\x60'"\s;]|\\[nr]|$)/g, { secretGroup:1, entropy:2, keywords:["tk-us-"] }),
  glRule("sendgrid-api-token", /\b(SG\.[A-Za-z0-9=_\-.]{66})(?:[\x60'"\s;]|\\[nr]|$)/gi, { secretGroup:1, entropy:2, keywords:["sg."] }),
  glRule("sendinblue-api-token", /\b(xkeysib-[a-f0-9]{64}-[a-z0-9]{16})(?:[\x60'"\s;]|\\[nr]|$)/gi, { secretGroup:1, entropy:2, keywords:["xkeysib-"] }),
  glRule("sentry-org-token", /\b(sntrys_eyJpYXQiO[A-Za-z0-9+/]{10,200}(?:LCJyZWdpb25fdXJs|InJlZ2lvbl91cmwi|cmVnaW9uX3VybCI6)[A-Za-z0-9+/]{10,200}={0,2}_[A-Za-z0-9+/]{43})(?:[^A-Za-z0-9+/]|$)/g, { secretGroup:1, entropy:4.5, keywords:["sntrys_eyjpyxqio"] }),
  glRule("sentry-user-token", /\b(sntryu_[a-f0-9]{64})(?:[\x60'"\s;]|\\[nr]|$)/g, { secretGroup:1, entropy:3.5, keywords:["sntryu_"] }),
  glRule("settlemint-application-access-token", /\b(sm_aat_[A-Za-z0-9]{16})(?:[\x60'"\s;]|\\[nr]|$)/g, { secretGroup:1, entropy:3, keywords:["sm_aat"] }),
  glRule("settlemint-personal-access-token", /\b(sm_pat_[A-Za-z0-9]{16})(?:[\x60'"\s;]|\\[nr]|$)/g, { secretGroup:1, entropy:3, keywords:["sm_pat"] }),
  glRule("settlemint-service-access-token", /\b(sm_sat_[A-Za-z0-9]{16})(?:[\x60'"\s;]|\\[nr]|$)/g, { secretGroup:1, entropy:3, keywords:["sm_sat"] }),
  glRule("shippo-api-token", /\b(shippo_(?:live|test)_[A-Fa-f0-9]{40})(?:[\x60'"\s;]|\\[nr]|$)/g, { secretGroup:1, entropy:2, keywords:["shippo_"] }),
  glRule("shopify-access-token", /(shpat_[A-Fa-f0-9]{32})/g, { secretGroup:1, entropy:2, keywords:["shpat_"] }),
  glRule("shopify-custom-access-token", /(shpca_[A-Fa-f0-9]{32})/g, { secretGroup:1, entropy:2, keywords:["shpca_"] }),
  glRule("shopify-private-app-access-token", /(shppa_[A-Fa-f0-9]{32})/g, { secretGroup:1, entropy:2, keywords:["shppa_"] }),
  glRule("shopify-shared-secret", /(shpss_[A-Fa-f0-9]{32})/g, { secretGroup:1, entropy:2, keywords:["shpss_"] }),
  glRule("slack-app-token", /(xapp-\d-[A-Z0-9]+-\d+-[a-z0-9]+)/gi, { secretGroup:1, entropy:2, keywords:["xapp"] }),
  glRule("slack-bot-token", /(xoxb-[0-9]{10,13}-[0-9]{10,13}[A-Za-z0-9-]*)/g, { secretGroup:1, entropy:3, keywords:["xoxb"] }),
  glRule("slack-config-access-token", /(xoxe.xox[bp]-\d-[A-Z0-9]{163,166})/gi, { secretGroup:1, entropy:2, keywords:["xoxe.xoxb-","xoxe.xoxp-"] }),
  glRule("slack-config-refresh-token", /(xoxe-\d-[A-Z0-9]{146})/gi, { secretGroup:1, entropy:2, keywords:["xoxe-"] }),
  glRule("slack-legacy-bot-token", /(xoxb-[0-9]{8,14}-[A-Za-z0-9]{18,26})/g, { secretGroup:1, entropy:2, keywords:["xoxb"] }),
  glRule("slack-legacy-token", /(xox[os]-\d+-\d+-\d+-[A-Fa-f\d]+)/g, { secretGroup:1, entropy:2, keywords:["xoxo","xoxs"] }),
  glRule("slack-legacy-workspace-token", /(xox[ar]-(?:\d-)?[0-9A-Za-z]{8,48})/g, { secretGroup:1, entropy:2, keywords:["xoxa","xoxr"] }),
  glRule("slack-user-token", /(xox[pe](?:-[0-9]{10,13}){3}-[A-Za-z0-9-]{28,34})/g, { secretGroup:1, entropy:2, keywords:["xoxp-","xoxe-"] }),
  glRule("slack-webhook-url", /((?:https?:\/\/)?hooks\.slack\.com\/(?:services|workflows|triggers)\/[A-Za-z0-9+/]{43,56})/g, { secretGroup:1, keywords:["hooks.slack.com"] }),
  glRule("sourcegraph-access-token", /\b((?:sgp_(?:[A-Fa-f0-9]{16}|local)_[A-Fa-f0-9]{40}|sgp_[A-Fa-f0-9]{40}))(?:[\x60'"\s;]|\\[nr]|$)/g, { secretGroup:1, entropy:3, keywords:["sgp_","sourcegraph"] }),
  glRule("square-access-token", /\b((?:EAAA|sq0atp-)[\w-]{22,60})(?:[\x60'"\s;]|\\[nr]|$)/g, { secretGroup:1, entropy:2, keywords:["sq0atp-","eaaa"] }),
  glRule("square-secret", /\b(sq0csp-[A-Za-z0-9_-]{20,})\b/g, { secretGroup:1, entropy:2, keywords:["sq0csp-"] }),
  glRule("stripe-access-token", /\b((?:sk|rk)_(?:test|live|prod)_[A-Za-z0-9]{10,99})(?:[\x60'"\s;]|\\[nr]|$)/g, { secretGroup:1, entropy:2, keywords:["sk_test","sk_live","sk_prod","rk_test","rk_live","rk_prod"] }),
  glRule("twilio-api-key", /\b(SK[0-9A-Fa-f]{32})\b/g, { secretGroup:1, entropy:3, keywords:["sk"] }),
  glRule("vault-batch-token", /\b(hvb\.[\w-]{138,300})(?:[\x60'"\s;]|\\[nr]|$)/g, { secretGroup:1, entropy:4, keywords:["hvb."] }),
  glRule("vault-service-token", /\b((?:hvs\.[\w-]{90,120}|s\.[a-z0-9]{24}))(?:[\x60'"\s;]|\\[nr]|$)/gi, { secretGroup:1, entropy:3.5, keywords:["hvs.","s."], allowRegexes:[/^s\.[A-Za-z]{24}$/] }),
  // Additional current upstream Gitleaks signatures that do not fit the generic assignment template.
  glRule("adobe-client-secret", /\b(p8e-[A-Za-z0-9]{32})(?:[\x60'"\s;]|\\[nr]|$)/gi, { secretGroup:1, entropy:2, keywords:["p8e-"] }),
  glRule("atlassian-api-token-routable", /\b(ATATT3[A-Za-z0-9_\-=]{186})(?:[\x60'"\s;]|\\[nr]|$)/g, { secretGroup:1, entropy:3.5, keywords:["atatt3"] }),
  glRule("authress-service-client-access-key", /\b((?:sc|ext|scauth|authress)_[A-Za-z0-9]{5,30}\.[A-Za-z0-9]{4,6}\.acc[_-][A-Za-z0-9-]{10,32}\.[A-Za-z0-9+/_=-]{30,120})(?:[\x60'"\s;]|\\[nr]|$)/gi, { secretGroup:1, entropy:2, keywords:["sc_","ext_","scauth_","authress_"] }),
  glRule("cloudflare-origin-ca-key", /\b(v1\.0-[a-f0-9]{24}-[a-f0-9]{146})(?:[\x60'"\s;]|\\[nr]|$)/gi, { secretGroup:1, entropy:2, keywords:["v1.0-","cloudflare"] }),
  glRule("duffel-api-token", /(duffel_(?:test|live)_[A-Za-z0-9_\-=]{43})/gi, { secretGroup:1, entropy:2, keywords:["duffel_"] }),
  glRule("dynatrace-api-token", /(dt0c01\.[A-Za-z0-9]{24}\.[A-Za-z0-9]{64})/gi, { secretGroup:1, entropy:4, keywords:["dt0c01."] }),
  glRule("easypost-api-token", /\b(EZAK[A-Za-z0-9]{54})\b/gi, { secretGroup:1, entropy:2, keywords:["ezak"] }),
  glRule("easypost-test-api-token", /\b(EZTK[A-Za-z0-9]{54})\b/gi, { secretGroup:1, entropy:2, keywords:["eztk"] }),
  glRule("facebook-access-token", /\b(\d{15,16}(?:\||%)[A-Za-z0-9_-]{27,40})(?:[\x60'"\s;]|\\[nr]|$)/gi, { secretGroup:1, entropy:3 }),
  glRule("facebook-page-access-token", /\b(EAA[MC][A-Za-z0-9]{100,})(?:[\x60'"\s;]|\\[nr]|$)/gi, { secretGroup:1, entropy:4, keywords:["eaam","eaac"] }),
  glRule("freemius-secret-key", /["']secret_key["']\s*=>\s*["'](sk_\S{29})["']/gi, { secretGroup:1, keywords:["secret_key"] }),
  glRule("gitlab-cicd-job-token", /(glcbt-[0-9A-Za-z]{1,5}_[0-9A-Za-z_-]{20})/g, { secretGroup:1, entropy:3, keywords:["glcbt-"] }),
  glRule("gitlab-runner-authentication-token-routable", /\b(glrt-t\d_[0-9A-Za-z_-]{27,300}\.[0-9a-z]{9})\b/g, { secretGroup:1, entropy:4, keywords:["glrt-"] }),
  glRule("jwt", /\b(ey[A-Za-z0-9]{17,}\.ey[A-Za-z0-9/_-]{17,}\.(?:[A-Za-z0-9/_-]{10,}={0,2})?)(?:[\x60'"\s;]|\\[nr]|$)/g, { secretGroup:1, entropy:3, keywords:["ey"] }),
  glRule("jwt-base64", /\b(ZXlK[A-Za-z0-9/_+\-\r\n]{40,}={0,2})/g, { secretGroup:1, entropy:2, keywords:["zxlk"] }),
  glRule("maxmind-license-key", /\b([A-Za-z0-9]{6}_[A-Za-z0-9]{29}_mmk)(?:[\x60'"\s;]|\\[nr]|$)/g, { secretGroup:1, entropy:4, keywords:["_mmk"] }),
  glRule("octopus-deploy-api-key", /\b(API-[A-Z0-9]{26})(?:[\x60'"\s;]|\\[nr]|$)/g, { secretGroup:1, entropy:3, keywords:["api-"] }),
  glRule("sidekiq-sensitive-url", /\bhttps?:\/\/([a-f0-9]{8}:[a-f0-9]{8})@(?:gems\.contribsys\.com|enterprise\.contribsys\.com)(?:[\/#?:]|$)/gi, { secretGroup:1, keywords:["gems.contribsys.com","enterprise.contribsys.com"] }),
  // curl's upstream RE2 rule has several alternate capture groups. Split it into
  // JS-friendly rules while preserving the actual credential as secretGroup 1.
  glRule("curl-auth-header-basic", /\bcurl\b[\s\S]{0,1000}?(?:-H|--header)(?:=|\s{0,5})["']?Authorization:\s{0,5}Basic\s+([A-Za-z0-9+/]{8,}={0,3})/gi, { secretGroup:1, entropy:2.75, keywords:["curl"] }),
  glRule("curl-auth-header-bearer", /\bcurl\b[\s\S]{0,1000}?(?:-H|--header)(?:=|\s{0,5})["']?Authorization:\s{0,5}(?:Bearer|(?:Api-)?Token)\s+([\w=~@.+/-]{8,})/gi, { secretGroup:1, entropy:2.75, keywords:["curl"] }),
  glRule("curl-api-header", /\bcurl\b[\s\S]{0,1000}?(?:-H|--header)(?:=|\s{0,5})["']?(?:(?:X-(?:[a-z]+-)?)?(?:Api-?)?(?:Key|Token)):\s{0,5}([\w=~@.+/-]{8,})/gi, { secretGroup:1, entropy:2.75, keywords:["curl"] }),
  glRule("curl-auth-user", /\bcurl\b[\s\S]{0,1000}?(?:-u|--user)(?:=|\s{0,5})["']?([^\s"']{3,}:[^\s"']{3,})/gi, { secretGroup:1, entropy:2, keywords:["curl"], allowRegexes:[/^[^:]+:(?:change(?:it|me)|pass(?:word)?|pwd|test|token|\*+|x+)$/i] }),
  // Path-conditioned upstream Kubernetes rule: in an LLM body there is no file
  // path, so content matching is intentionally executed regardless of path.
  glRule("kubernetes-secret-yaml", /\bkind:\s*["']?secret\b[\s\S]{0,300}?\bdata:[\s\S]{0,150}?\b[\w.-]+:\s*["']?([A-Za-z0-9+/]{10,}={0,3})["']?/gi, { secretGroup:1, keywords:["secret","data:"] }),
  glRule("nuget-config-password", /<add\s+key="(?:ClearText)?Password"\s*value="(.{8,})"\s*\/>/gi, { secretGroup:1, entropy:1, keywords:["<add key="] , allowRegexes:[/^33f!!lloppa$/i,/^hal\+9ooo_da!sY$/i,/^%\S.*%$/] }),
  glRule("sourcegraph-bare-access-token", /\b([a-f0-9]{40})\b/gi, { secretGroup:1, entropy:3, keywords:["sourcegraph"] }),
];

const GITLEAK_ASSIGNMENT_RULES = [
  assignmentRule("adafruit-api-key", ["adafruit"], "[a-z0-9_-]{32}"),
  assignmentRule("adobe-client-id", ["adobe"], "[a-f0-9]{32}", { entropy:2 }),
  assignmentRule("airtable-api-key", ["airtable"], "[a-z0-9]{17}"),
  assignmentRule("algolia-api-key", ["algolia"], "[a-z0-9]{32}"),
  assignmentRule("alibaba-secret-key", ["alibaba"], "[a-z0-9]{30}", { entropy:2 }),
  assignmentRule("asana-client-id", ["asana"], "[0-9]{16}"),
  assignmentRule("asana-client-secret", ["asana"], "[a-z0-9]{32}"),
  assignmentRule("atlassian-api-token", ["atlassian","confluence","jira"], "[a-z0-9]{24}", { entropy:3.5, keySource:"atlassian|confluence|jira" }),
  assignmentRule("beamer-api-token", ["beamer"], "b_[a-z0-9=_-]{44}"),
  assignmentRule("bitbucket-client-id", ["bitbucket"], "[a-z0-9]{32}"),
  assignmentRule("bitbucket-client-secret", ["bitbucket"], "[a-z0-9=_-]{64}"),
  assignmentRule("bittrex-access-key", ["bittrex"], "[a-z0-9]{32}"),
  assignmentRule("bittrex-secret-key", ["bittrex"], "[a-z0-9]{32}"),
  assignmentRule("cisco-meraki-api-key", ["meraki"], "[0-9a-f]{40}", { entropy:3 }),
  assignmentRule("cloudflare-api-key", ["cloudflare"], "[a-z0-9_-]{40}", { entropy:2 }),
  assignmentRule("cloudflare-global-api-key", ["cloudflare"], "[a-f0-9]{37}", { entropy:2 }),
  assignmentRule("etsy-access-token", ["etsy"], "[a-z0-9]{24}", { entropy:3 }),
  assignmentRule("facebook-secret", ["facebook"], "[a-f0-9]{32}", { entropy:3 }),
  assignmentRule("fastly-api-token", ["fastly"], "[a-z0-9=_-]{32}"),
  assignmentRule("codecov-access-token", ["codecov"], "[a-z0-9]{32}"),
  assignmentRule("cohere-api-token", ["cohere","CO_API_KEY"], "[A-Za-z0-9]{40}", { entropy:4 }),
  assignmentRule("coinbase-access-token", ["coinbase"], "[a-z0-9_-]{64}"),
  assignmentRule("confluent-access-token", ["confluent"], "[a-z0-9]{16}"),
  assignmentRule("confluent-secret-key", ["confluent"], "[a-z0-9]{64}"),
  assignmentRule("contentful-delivery-api-token", ["contentful"], "[a-z0-9=_-]{43}"),
  assignmentRule("datadog-access-token", ["datadog"], "[a-z0-9]{40}"),
  assignmentRule("discord-api-token", ["discord"], "[a-f0-9]{64}"),
  assignmentRule("discord-client-id", ["discord"], "[0-9]{18}", { entropy:2 }),
  assignmentRule("discord-client-secret", ["discord"], "[a-z0-9=_-]{32}", { entropy:2 }),
  assignmentRule("droneci-access-token", ["droneci"], "[a-z0-9]{32}"),
  assignmentRule("dropbox-api-token", ["dropbox"], "[a-z0-9]{15}"),
  assignmentRule("dropbox-long-lived-api-token", ["dropbox"], "[a-z0-9]{11}AAAAAAAAAA[a-z0-9=_-]{43}"),
  assignmentRule("finicity-api-token", ["finicity"], "[a-f0-9]{32}"),
  assignmentRule("finicity-client-secret", ["finicity"], "[a-z0-9]{20}"),
  assignmentRule("finnhub-access-token", ["finnhub"], "[a-z0-9]{20}"),
  assignmentRule("flickr-access-token", ["flickr"], "[a-z0-9]{32}"),
  assignmentRule("freshbooks-access-token", ["freshbooks"], "[a-z0-9]{64}"),
  assignmentRule("hashicorp-tf-password", ["administrator_login_password","password"], "[a-z0-9=_-]{8,20}", { entropy:2, keySource:"administrator_login_password|password" }),
  assignmentRule("heroku-api-key", ["heroku"], "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
  assignmentRule("hubspot-api-key", ["hubspot"], "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
  assignmentRule("intercom-api-key", ["intercom"], "[a-z0-9=_-]{60}"),
  assignmentRule("gitter-access-token", ["gitter"], "[a-z0-9_-]{40}"),
  assignmentRule("gocardless-api-token", ["gocardless","live_"], "live_[a-z0-9_\\-=]{40}", { keySource:"gocardless" }),
  assignmentRule("jfrog-api-key", ["jfrog","artifactory","bintray","xray"], "[a-z0-9]{73}", { keySource:"jfrog|artifactory|bintray|xray" }),
  assignmentRule("jfrog-identity-token", ["jfrog","artifactory","bintray","xray"], "[a-z0-9]{64}", { keySource:"jfrog|artifactory|bintray|xray" }),
  assignmentRule("kraken-access-token", ["kraken"], "[a-z0-9/=_+\\-]{80,90}"),
  assignmentRule("kucoin-access-token", ["kucoin"], "[a-f0-9]{24}"),
  assignmentRule("kucoin-secret-key", ["kucoin"], "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
  assignmentRule("launchdarkly-access-token", ["launchdarkly"], "[a-z0-9=_-]{40}"),
  assignmentRule("linear-client-secret", ["linear"], "[a-f0-9]{32}", { entropy:2 }),
  assignmentRule("linkedin-client-id", ["linkedin","linked_in","linked-in"], "[a-z0-9]{14}", { entropy:2, keySource:"linked[_-]?in" }),
  assignmentRule("linkedin-client-secret", ["linkedin","linked_in","linked-in"], "[a-z0-9]{16}", { entropy:2, keySource:"linked[_-]?in" }),
  assignmentRule("lob-api-key", ["lob","test_","live_"], "(?:live|test)_[a-f0-9]{35}", { keySource:"lob" }),
  assignmentRule("lob-pub-api-key", ["lob","test_pub","live_pub"], "(?:test|live)_pub_[a-f0-9]{31}", { keySource:"lob" }),
  assignmentRule("looker-client-id", ["looker"], "[a-z0-9]{20}"),
  assignmentRule("looker-client-secret", ["looker"], "[a-z0-9]{24}"),
  assignmentRule("mailchimp-api-key", ["mailchimp","MailchimpSDK.initialize"], "[a-f0-9]{32}-us\\d{2}", { keySource:"MailchimpSDK\\.initialize|mailchimp" }),
  assignmentRule("messagebird-client-id", ["messagebird","message-bird","message_bird"], "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", { keySource:"message[_-]?bird" }),
  assignmentRule("netlify-access-token", ["netlify"], "[a-z0-9=_-]{40,46}"),
  assignmentRule("new-relic-insert-key", ["new-relic","newrelic","new_relic","nrii-"], "NRII-[a-z0-9-]{32}", { keySource:"new-relic|newrelic|new_relic" }),
  assignmentRule("new-relic-user-api-id", ["new-relic","newrelic","new_relic"], "[a-z0-9]{64}", { keySource:"new-relic|newrelic|new_relic" }),
  assignmentRule("nytimes-access-token", ["nytimes","new-york-times","newyorktimes"], "[a-z0-9=_-]{32}", { keySource:"nytimes|new-york-times|newyorktimes" }),
  assignmentRule("okta-access-token", ["okta"], "00[\\w=-]{40}", { entropy:4 }),
  assignmentRule("plaid-api-token", ["plaid"], "access-(?:sandbox|development|production)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
  assignmentRule("plaid-client-id", ["plaid"], "[a-z0-9]{24}", { entropy:3.5 }),
  assignmentRule("plaid-secret-key", ["plaid"], "[a-z0-9]{30}", { entropy:3.5 }),
  assignmentRule("privateai-api-token", ["privateai","private_ai","private-ai"], "[a-z0-9]{32}", { entropy:3, keySource:"private[_-]?ai" }),
  assignmentRule("rapidapi-access-token", ["rapidapi"], "[a-z0-9_-]{50}"),
  assignmentRule("sendbird-access-id", ["sendbird"], "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
  assignmentRule("sendbird-access-token", ["sendbird"], "[a-f0-9]{40}"),
  assignmentRule("sentry-access-token", ["sentry"], "[a-f0-9]{64}", { entropy:3 }),
  assignmentRule("snyk-api-token", ["snyk"], "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", { keySource:"snyk[_.-]?(?:(?:api|oauth)[_.-]?)?(?:key|token)" }),
  assignmentRule("sonar-api-token", ["sonar"], "(?:squ_|sqp_|sqa_)?[a-z0-9=_-]{40}", { keySource:"sonar[_.-]?(?:login|token)" }),
  assignmentRule("squarespace-access-token", ["squarespace"], "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
  assignmentRule("sidekiq-secret", ["bundle_enterprise__contribsys__com","bundle_gems__contribsys__com"], "[a-f0-9]{8}:[a-f0-9]{8}", { keySource:"BUNDLE_ENTERPRISE__CONTRIBSYS__COM|BUNDLE_GEMS__CONTRIBSYS__COM" }),
  assignmentRule("sumologic-access-id", ["sumo"], "su[A-Za-z0-9]{12}", { entropy:3 }),
  assignmentRule("sumologic-access-token", ["sumo"], "[a-z0-9]{64}", { entropy:3 }),
  assignmentRule("telegram-bot-api-token", ["telegr","telegram"], "[0-9]{5,16}:A[a-z0-9_-]{34}", { keySource:"telegr(?:am)?" }),
  assignmentRule("travisci-access-token", ["travis"], "[a-z0-9]{22}"),
  assignmentRule("twitch-api-token", ["twitch"], "[a-z0-9]{30}"),
  assignmentRule("twitter-access-secret", ["twitter"], "[a-z0-9]{45}"),
  assignmentRule("twitter-access-token", ["twitter"], "[0-9]{15,25}-[A-Za-z0-9]{20,40}"),
  assignmentRule("twitter-api-key", ["twitter"], "[a-z0-9]{25}"),
  assignmentRule("twitter-api-secret", ["twitter"], "[a-z0-9]{50}"),
  assignmentRule("twitter-bearer-token", ["twitter"], "A{22}[A-Za-z0-9%]{80,100}"),
  assignmentRule("typeform-api-token", ["typeform","tfp_"], "tfp_[a-z0-9_.=-]{59}", { keywords:["tfp_"] }),
  assignmentRule("yandex-access-token", ["yandex"], "t1\\.[A-Za-z0-9_-]+={0,2}\\.[A-Za-z0-9_-]{86}={0,2}"),
  assignmentRule("yandex-api-key", ["yandex"], "AQVN[A-Za-z0-9_-]{35,38}"),
  assignmentRule("yandex-aws-access-token", ["yandex"], "YC[A-Za-z0-9_-]{38}"),
  assignmentRule("zendesk-secret-key", ["zendesk"], "[a-z0-9]{40}"),
];

const GENERIC_GITLEAK_STOPWORDS = [
  // Privacy proxy bias: retain only high-confidence placeholder words here.
  // The upstream global stopword list is broader, but false negatives are more
  // damaging for this use case than a modest increase in false positives.
  "example", "sample", "dummy", "placeholder", "changeme",
  "localhost", "undefined", "null", "true", "false",
];

const GITLEAK_RULES = [
  ...GITLEAK_DIRECT_RULES,
  ...GITLEAK_ASSIGNMENT_RULES,
  assignmentRule(
    "generic-api-key",
    ["access","auth","api","credential","creds","key","passwd","password","secret","token"],
    "(?:[\\w.=-]{10,150}|[a-z0-9][a-z0-9+/]{11,}={0,3})",
    {
      entropy: 3.5,
      keySource: "access|auth|api|credential|creds|key|passw(?:or)?d|secret|token",
      allowRegexes: [/^[A-Za-z_.-]+$/],
      stopwords: GENERIC_GITLEAK_STOPWORDS,
    },
  ),
];

export const GITLEAK_PORTABLE_RULE_COUNT = GITLEAK_RULES.length;

function collectGitleakSpans(text) {
  const out = [];
  const lower = text.toLowerCase();
  for (const rule of GITLEAK_RULES) {
    if (rule.keywords.length && !rule.keywords.some((k) => lower.includes(k))) continue;
    const re = rule.regex;
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(text))) {
      if (!m[0].length) { re.lastIndex++; continue; }
      const secret = rule.secretGroup ? m[rule.secretGroup] : m[0];
      if (!secret) continue;
      const relative = rule.secretGroup ? m[0].indexOf(secret) : 0;
      if (relative < 0) continue;
      if (rule.entropy && shannonEntropy(secret) < rule.entropy) continue;
      const secretLower = secret.toLowerCase();
      if (rule.stopwords.some((word) => secretLower.includes(word))) continue;
      if (rule.allowRegexes.some((allow) => { allow.lastIndex = 0; return allow.test(secret); })) continue;
      out.push({
        start: m.index + relative,
        end: m.index + relative + secret.length,
        type: "gitleaks",
        priority: 120,
        ruleId: rule.id,
      });
    }
  }
  return out;
}


function collectRegexSpans(text, regex, type, priority, validator = null) {
  const out = [];
  regex.lastIndex = 0;
  let m;
  while ((m = regex.exec(text))) {
    if (!m[0].length) { regex.lastIndex++; continue; }
    if (!validator || validator(m[0])) out.push({ start:m.index, end:m.index + m[0].length, type, priority });
  }
  return out;
}

function overlaps(a, b) { return a.start < b.end && a.end > b.start; }

export function findSensitiveSpans(text, flags, manualWords = []) {
  const protectedSpans = collectRegexSpans(text, /\{\{Redact:[a-f0-9]{64}\}\}/g, "existing", 1000);
  const c = [];
  if (flags.manual) {
    for (const word of manualWords) {
      if (!word) continue;
      let start = text.indexOf(word);
      while (start !== -1) {
        c.push({ start, end: start + word.length, type: "manual", priority: 130 });
        start = text.indexOf(word, start + 1);
      }
    }
  }
  if (flags.secret) c.push(...collectRegexSpans(text, /\bsk-[A-Za-z0-9]{60,}\b/g, "secret", 110));
  if (flags.email) c.push(...collectRegexSpans(text, /[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+/g, "email", 90));
  if (flags.identity) c.push(...collectRegexSpans(text, /(?<!\d)\d{17}[0-9Xx](?!\d)/g, "identity", 100, (s) => chinaIdValid(s)));
  if (flags.bank) {
    const bankValid = (s) => { const d=s.replace(/\D/g,""); return d.length>=13 && d.length<=19 && luhnValid(d); };
    c.push(...collectRegexSpans(text, /(?<!\d)\d{13,19}(?!\d)/g, "bank", 85, bankValid));
    c.push(...collectRegexSpans(text, /(?<!\d)\d{4}(?:[ -]\d{4}){2,3}(?:[ -]\d{1,3})?(?!\d)/g, "bank", 85, bankValid));
  }
  if (flags.phone) {
    c.push(...collectRegexSpans(text, /(?<!\d)1[3-9]\d{9}(?!\d)/g, "phone", 88));
    c.push(...collectRegexSpans(text, /(?<!\d)\+(?:\d[ .()\-]?){7,14}\d(?!\d)/g, "phone", 88));
  }
  if (flags.gitleaks) c.push(...collectGitleakSpans(text));
  if (flags.highEntropy) for (const b of tokenizeBlocks(text)) if (isHighEntropyBlock(b.value)) c.push({ start:b.start, end:b.end, type:"entropy", priority:10 });

  const candidates = c.filter((x) => !protectedSpans.some((p) => overlaps(x, p)));
  candidates.sort((a,b) => b.priority-a.priority || (b.end-b.start)-(a.end-a.start) || a.start-b.start);
  const selected = [];
  for (const s of candidates) if (!selected.some((x) => overlaps(s,x))) selected.push(s);
  return selected.sort((a,b) => a.start-b.start);
}

export class RedactionLimitError extends Error {}

export class RedactionContext {
  constructor({ salt = getRuntimeSalt(), maxRedactions = DEFAULT_MAX_REDACTIONS, parseNestedJson = true, manualWords = [] } = {}) {
    this.salt = salt;
    this.maxRedactions = maxRedactions;
    this.parseNestedJson = parseNestedJson;
    this.manualWords = manualWords;
    this.rawToToken = new Map();
    this.tokenToRaw = new Map();
  }
  async tokenFor(raw) {
    if (this.rawToToken.has(raw)) return this.rawToToken.get(raw);
    if (this.rawToToken.size >= this.maxRedactions) throw new RedactionLimitError(`Redaction limit exceeded (${this.maxRedactions})`);
    const digest = await crypto.subtle.digest("SHA-256", textEncoder.encode(raw + this.salt));
    const hex = Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2,"0")).join("");
    const token = TOKEN_PREFIX + hex + TOKEN_SUFFIX;
    const collision = this.tokenToRaw.get(token);
    if (collision !== undefined && collision !== raw) throw new Error("SHA-256 redaction token collision");
    this.rawToToken.set(raw, token); this.tokenToRaw.set(token, raw);
    return token;
  }
  async redactText(text, flags) {
    const spans = findSensitiveSpans(text, flags, this.manualWords);
    if (!spans.length) return text;
    let out = "", at = 0;
    for (const s of spans) {
      out += text.slice(at, s.start);
      out += await this.tokenFor(text.slice(s.start, s.end));
      at = s.end;
    }
    return out + text.slice(at);
  }
  restoreText(text) {
    return text.replace(TOKEN_RE, (token) => this.tokenToRaw.get(token) ?? token);
  }
}

const CONTROL_KEYS = new Set(["model","role","type","id","object","status","name","call_id","tool_call_id","tool_use_id","finish_reason","stop_reason","media_type","mime_type","encoding","format"]);
function shouldSkipString(path) {
  const key = path[path.length - 1] || "";
  if (CONTROL_KEYS.has(key)) return true;
  const p = path.join(".").toLowerCase();
  if (/(?:image_url|input_image|input_audio|audio|file_data|b64_json|source\.data|image\.data)/.test(p)) return true;
  if (key === "url" || key === "image_url") return true;
  return false;
}

const CHAT_REASONING_KEYS = new Set(["reasoning_content", "reasoning", "reasoning_details"]);

function isRequestModelState(protocol, root, path, value) {
  // Historical assistant reasoning/thinking is upstream-generated model state.
  // Recognition is protocol-, path-, and role-aware; field names alone never bypass redaction.
  if (protocol === "openai_responses") {
    return path.length === 2 && path[0] === "input" && /^\d+$/.test(path[1]) &&
      value && typeof value === "object" && !Array.isArray(value) &&
      (value.type === "reasoning" || value.type === "compaction");
  }
  if (protocol === "anthropic_messages") {
    if (path.length !== 4 || path[0] !== "messages" || path[2] !== "content" ||
        !/^\d+$/.test(path[1]) || !/^\d+$/.test(path[3])) return false;
    const message = root?.messages?.[Number(path[1])];
    return message?.role === "assistant" && value && typeof value === "object" && !Array.isArray(value) &&
      (value.type === "thinking" || value.type === "redacted_thinking");
  }
  if (protocol === "openai_chat") {
    if (path.length !== 3 || path[0] !== "messages" || !/^\d+$/.test(path[1]) ||
        !CHAT_REASONING_KEYS.has(path[2])) return false;
    return root?.messages?.[Number(path[1])]?.role === "assistant";
  }
  return false;
}

export async function redactJson(value, ctx, flags, protocol = "generic", path = [], root = value) {
  if (isRequestModelState(protocol, root, path, value)) return value;
  // Cache routing keys are opaque protocol metadata. Expanding a UUID into a
  // redaction placeholder can exceed the upstream's key length limit.
  // Scope this exception to the request root, not user/tool JSON with this key.
  if ((protocol === "openai_responses" || protocol === "openai_chat") &&
      path.length === 1 && path[0] === "prompt_cache_key" && typeof value === "string") return value;
  if (typeof value === "string") {
    if (!shouldSkipString(path) && ctx.parseNestedJson && /^[\s]*[\[{]/.test(value)) {
      try {
        const nested = JSON.parse(value);
        if (nested && typeof nested === "object") {
          const redacted = await redactJson(nested, ctx, flags, protocol, path.concat("<nested-json>"), root);
          return JSON.stringify(redacted);
        }
      } catch { /* Treat non-JSON strings as ordinary text. */ }
    }
    return shouldSkipString(path) ? value : ctx.redactText(value, flags);
  }
  if (Array.isArray(value)) {
    const out = [];
    for (let i=0;i<value.length;i++) out.push(await redactJson(value[i], ctx, flags, protocol, path.concat(String(i)), root));
    return out;
  }
  if (value && typeof value === "object") {
    const out = {};
    for (const [k,v] of Object.entries(value)) out[k] = await redactJson(v, ctx, flags, protocol, path.concat(k), root);
    return out;
  }
  return value;
}

export function restoreJson(value, ctx) {
  if (typeof value === "string") return ctx.restoreText(value);
  if (Array.isArray(value)) return value.map((v) => restoreJson(v, ctx));
  if (value && typeof value === "object") { for (const k of Object.keys(value)) value[k] = restoreJson(value[k], ctx); }
  return value;
}

export function detectProtocol(body, upstream, headers) {
  const p = upstream.pathname.toLowerCase();
  if (/\/chat\/completions\/?$/.test(p)) return "openai_chat";
  if (/\/responses\/?$/.test(p)) return "openai_responses";
  if (/\/messages\/?$/.test(p)) return "anthropic_messages";
  if (body && Array.isArray(body.messages)) return headers?.get?.("anthropic-version") ? "anthropic_messages" : "openai_chat";
  if (body && (typeof body.input === "string" || Array.isArray(body.input))) return "openai_responses";
  return "generic";
}

function prependToContent(message, protocol) {
  const prefix = REDACT_NOTICE + "\n\n";
  if (typeof message.content === "string") { message.content = prefix + message.content; return true; }
  if (Array.isArray(message.content)) {
    for (const block of message.content) {
      if (block && typeof block === "object" && typeof block.text === "string" && (block.type === "text" || block.type === "input_text" || !block.type)) { block.text = prefix + block.text; return true; }
    }
    message.content.unshift({ type: protocol === "openai_responses" ? "input_text" : "text", text: REDACT_NOTICE });
    return true;
  }
  message.content = prefix;
  return true;
}

export function injectRedactNotice(body, protocol, options = {}) {
  if (options.enabled === false) return false;
  const position = options.position || "first_user";
  if (position !== "first_user" && position !== "last_user") throw new Error("REDACT_NOTICE_POSITION must be 'first_user' or 'last_user'");
  if (!body || typeof body !== "object") return false;
  if (protocol === "openai_responses") {
    if (typeof body.input === "string") { body.input = REDACT_NOTICE + "\n\n" + body.input; return true; }
    if (Array.isArray(body.input)) {
      const start = position === "first_user" ? 0 : body.input.length - 1;
      const end = position === "first_user" ? body.input.length : -1;
      const step = position === "first_user" ? 1 : -1;
      for (let i = start; i !== end; i += step) {
        const item = body.input[i];
        if (item && item.role === "user") return prependToContent(item, protocol);
      }
      return false;
    }
  }
  if (Array.isArray(body.messages)) {
    const start = position === "first_user" ? 0 : body.messages.length - 1;
    const end = position === "first_user" ? body.messages.length : -1;
    const step = position === "first_user" ? 1 : -1;
    for (let i = start; i !== end; i += step) {
      const m = body.messages[i];
      if (m && m.role === "user") return prependToContent(m, protocol);
    }
  }
  return false;
}

function filteredRequestHeaders(headers) {
  const out = new Headers(headers);
  const exact = new Set([
    "host","content-length","connection","transfer-encoding","keep-alive",
    "proxy-authenticate","proxy-authorization","te","trailer","upgrade","accept-encoding",
    "x-forwarded-for","x-forwarded-proto","x-real-ip","forwarded","via",
    "cookie","cookie2"
  ]);
  for (const [name] of [...out]) {
    const k = name.toLowerCase();
    if (exact.has(k) || k.startsWith("cf-") || k.startsWith("sec-")) out.delete(name);
  }
  return out;
}

function withCors(headers, origin = "*") {
  const h = new Headers(headers);
  h.set("access-control-allow-origin", origin || "*");
  h.set("access-control-expose-headers", "*");
  h.delete("content-length");
  return h;
}

function corsPreflight(request, origin = "*") {
  const h = new Headers();
  h.set("access-control-allow-origin", origin || "*");
  h.set("access-control-allow-methods", "GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS");
  h.set("access-control-allow-headers", request.headers.get("access-control-request-headers") || "authorization,content-type,x-api-key,anthropic-version,openai-organization,openai-project");
  h.set("access-control-max-age", "86400");
  return new Response(null, { status:204, headers:h });
}

function intSetting(v, fallback) { const n = Number(v); return Number.isFinite(n) && n > 0 ? Math.floor(n) : fallback; }
function allowedHost(upstream, env) {
  const raw = env?.REDACT_ALLOWED_HOSTS;
  if (!raw) return true;
  const allow = raw.split(",").map((x)=>x.trim().toLowerCase()).filter(Boolean);
  return allow.some((h) => upstream.hostname.toLowerCase() === h || upstream.hostname.toLowerCase().endsWith("." + h));
}
function jsonError(status, message) { return new Response(JSON.stringify({ error: { message, type:"cosy_redact_gateway_error" } }), { status, headers:{"content-type":"application/json; charset=utf-8"} }); }

function isJsonContentType(ct) { return /(^|[+\/])json(?:$|[; ])/i.test(ct || "") || /application\/.*\+json/i.test(ct || ""); }
function isTextualContentType(ct) { return isJsonContentType(ct) || /^text\//i.test(ct || "") || /javascript|xml/i.test(ct || ""); }

function possibleTokenSuffixLength(s) {
  const last = s.lastIndexOf(TOKEN_PREFIX);
  if (last >= 0) {
    const tail = s.slice(last);
    if (tail.length < TOKEN_LENGTH) {
      const rest = tail.slice(TOKEN_PREFIX.length);
      if (tail.length <= TOKEN_PREFIX.length || /^[a-f0-9]{0,64}}?$/.test(rest)) return s.length - last;
    }
  }
  const max = Math.min(TOKEN_PREFIX.length - 1, s.length);
  for (let k=max;k>0;k--) if (s.endsWith(TOKEN_PREFIX.slice(0,k))) return k;
  return 0;
}

function parseSseEvent(raw) {
  const lines = raw.split("\n");
  const data = [], nonData = [];
  let insertAt = -1, eventName = "";
  for (const line of lines) {
    if (line.startsWith("data:")) { if (insertAt < 0) insertAt = nonData.length; data.push(line.slice(5).replace(/^ /,"")); }
    else { if (line.startsWith("event:")) eventName = line.slice(6).trim(); nonData.push(line); }
  }
  return { raw, lines, dataText:data.join("\n"), nonData, insertAt, eventName };
}

function serializeSseEvent(parsed, dataText) {
  if (parsed.insertAt < 0) return parsed.raw + "\n\n";
  const lines = parsed.nonData.slice();
  lines.splice(parsed.insertAt, 0, "data: " + dataText);
  return lines.join("\n") + "\n\n";
}

function getAt(obj, path) { let x=obj; for (let i=0;i<path.length-1;i++) x=x?.[path[i]]; return x; }
function collectStringLeaves(value, basePath, channelPrefix, fields, local = []) {
  if (!value || typeof value !== "object") return;
  for (const [key, child] of Object.entries(value)) {
    const next = local.concat(key);
    if (typeof child === "string") {
      // Metadata fields are not streamed user/model text and must not be coalesced.
      if (["role","type","id","object","status","finish_reason","stop_reason"].includes(key)) continue;
      fields.push({ path:basePath.concat(next), channel:`${channelPrefix}:${next.join(".")}` });
    } else if (child && typeof child === "object") {
      collectStringLeaves(child, basePath, channelPrefix, fields, next);
    }
  }
}

function streamFields(data, eventName="") {
  const fields=[];
  if (Array.isArray(data?.choices)) {
    data.choices.forEach((choice, ci) => {
      if (choice?.delta && typeof choice.delta === "object") {
        collectStringLeaves(choice.delta,["choices",ci,"delta"],`chat:${choice.index ?? ci}:delta`,fields);
      }
      // Some compatible providers use a legacy text delta.
      if (typeof choice?.text === "string") fields.push({ path:["choices",ci,"text"], channel:`chat:${choice.index ?? ci}:text` });
    });
  }
  const typ = data?.type || eventName || "event";
  if (typeof data?.delta === "string" && /delta/i.test(typ)) {
    fields.push({ path:["delta"], channel:`responses:${typ}:${data.output_index ?? ""}:${data.content_index ?? ""}:${data.item_id ?? ""}` });
  } else if (data?.delta && typeof data.delta === "object") {
    collectStringLeaves(data.delta,["delta"],`delta:${typ}:${data.index ?? ""}`,fields);
  }
  return fields;
}

function restoreCompleteStrings(value, ctx, excluded = new Set(), path = []) {
  if (typeof value === "string") return excluded.has(path.join(".")) ? value : ctx.restoreText(value);
  if (Array.isArray(value)) { for (let i=0;i<value.length;i++) value[i]=restoreCompleteStrings(value[i],ctx,excluded,path.concat(String(i))); return value; }
  if (value && typeof value === "object") { for (const k of Object.keys(value)) value[k]=restoreCompleteStrings(value[k],ctx,excluded,path.concat(k)); }
  return value;
}

class SseRestorer {
  constructor(ctx) { this.ctx=ctx; this.channels=new Map(); this.queue=[]; }
  ingest(raw) {
    const parsed=parseSseEvent(raw);
    const payload=parsed.dataText;
    if (!payload || payload === "[DONE]") { this.queue.push({safe:true, output:raw+"\n\n"}); return this.drain(); }
    let data;
    try { data=JSON.parse(payload); } catch { this.queue.push({safe:true, output:serializeSseEvent(parsed,this.ctx.restoreText(payload))}); return this.drain(); }
    const fields=streamFields(data, parsed.eventName);
    const excluded=new Set(fields.map((f)=>f.path.join(".")));
    restoreCompleteStrings(data,this.ctx,excluded);
    const ev={safe:fields.length===0,pending:fields.length,parsed,data,output:null};
    this.queue.push(ev);
    const affected=new Set();
    for (const f of fields) {
      const parent=getAt(data,f.path), key=f.path[f.path.length-1], source=parent[key];
      let ch=this.channels.get(f.channel); if (!ch) this.channels.set(f.channel,ch={text:"",records:[]});
      ch.text += source; ch.records.push({ev,parent,key}); affected.add(f.channel);
    }
    for (const key of affected) this.maybeFlushChannel(key,false);
    return this.drain();
  }
  maybeFlushChannel(key,force) {
    const ch=this.channels.get(key); if (!ch || !ch.records.length) return;
    if (!force && possibleTokenSuffixLength(ch.text)>0) return;
    const restored=this.ctx.restoreText(ch.text);
    for (const r of ch.records) r.parent[r.key]="";
    const last=ch.records[ch.records.length-1]; last.parent[last.key]=restored;
    for (const r of ch.records) { r.ev.pending--; if (r.ev.pending===0) r.ev.safe=true; }
    ch.text=""; ch.records=[];
  }
  finish() { for (const key of this.channels.keys()) this.maybeFlushChannel(key,true); return this.drain(true); }
  drain(force=false) {
    let out="";
    while (this.queue.length && (this.queue[0].safe || force)) {
      const ev=this.queue.shift();
      if (ev.output != null) out += ev.output;
      else if (ev.data !== undefined) out += serializeSseEvent(ev.parsed, JSON.stringify(ev.data));
      else out += ev.parsed?.raw ? ev.parsed.raw+"\n\n" : "";
    }
    return out;
  }
}

export function restoreSseStream(body, ctx) {
  const reader=body.getReader();
  const decoder=new TextDecoder();
  const encoder=new TextEncoder();
  const restorer=new SseRestorer(ctx);
  let buffer="";
  let upstreamDone=false;
  let restorerFinished=false;

  function normalize() { buffer=buffer.replace(/\r\n/g,"\n"); }

  return new ReadableStream({
    async pull(controller) {
      try {
        while (true) {
          const idx=buffer.indexOf("\n\n");
          if (idx >= 0) {
            const raw=buffer.slice(0,idx);
            buffer=buffer.slice(idx+2);
            const produced=restorer.ingest(raw);
            if (produced) { controller.enqueue(encoder.encode(produced)); return; }
            continue;
          }

          if (upstreamDone) {
            if (buffer.length) {
              const raw=buffer; buffer="";
              const produced=restorer.ingest(raw);
              if (produced) { controller.enqueue(encoder.encode(produced)); return; }
              continue;
            }
            if (!restorerFinished) {
              restorerFinished=true;
              const final=restorer.finish();
              if (final) { controller.enqueue(encoder.encode(final)); return; }
            }
            controller.close();
            return;
          }

          const {done,value}=await reader.read();
          if (done) {
            buffer += decoder.decode();
            normalize();
            upstreamDone=true;
          } else {
            buffer += decoder.decode(value,{stream:true});
            normalize();
          }
        }
      } catch (e) {
        controller.error(e);
        try { await reader.cancel(e); } catch {}
      }
    },
    async cancel(reason) { try { await reader.cancel(reason); } catch {} }
  });
}

async function restoreNonStreamResponse(upstreamResponse, ctx, corsOrigin) {
  const headers=withCors(upstreamResponse.headers,corsOrigin); headers.delete("content-encoding");
  if (!upstreamResponse.body || upstreamResponse.status===204 || upstreamResponse.status===304) return new Response(null,{status:upstreamResponse.status,statusText:upstreamResponse.statusText,headers});
  const ct=headers.get("content-type") || "";
  if (!isTextualContentType(ct)) return new Response(upstreamResponse.body,{status:upstreamResponse.status,statusText:upstreamResponse.statusText,headers});
  const text=await upstreamResponse.text();
  let out=text;
  if (isJsonContentType(ct)) {
    try { const data=JSON.parse(text); restoreJson(data,ctx); out=JSON.stringify(data); } catch { out=ctx.restoreText(text); }
  } else out=ctx.restoreText(text);
  return new Response(out,{status:upstreamResponse.status,statusText:upstreamResponse.statusText,headers});
}

export async function handleRequest(request, env = {}, options = {}) {
  const corsOrigin=env?.REDACT_CORS_ORIGIN || "*";
  if (request.method === "OPTIONS") return corsPreflight(request,corsOrigin);
  const url=new URL(request.url);
  if (url.pathname === "/" || url.pathname === "/healthz") {
    return new Response(JSON.stringify({ok:true,service:"cosy-redact-gateway",route:"/<flags>$<upstream-url>",flags:ALL_FLAG_LETTERS,defaultAll:true}),{headers:withCors({"content-type":"application/json; charset=utf-8"},corsOrigin)});
  }
  let target;
  const blockPrivate = !/^(0|false|no|off)$/i.test(String(env?.REDACT_BLOCK_PRIVATE_UPSTREAMS ?? "true"));
  try { target=parseProxyTarget(request.url, { blockPrivate }); } catch(e) { return jsonError(400,e.message); }
  if (!target) return jsonError(404,"Expected /<flags>$<upstream-url>");
  if (!allowedHost(target.upstream,env)) return jsonError(403,"Upstream host is not in REDACT_ALLOWED_HOSTS");

  const maxBody=intSetting(env?.REDACT_MAX_BODY_BYTES,DEFAULT_MAX_BODY_BYTES);
  const maxRedactions=intSetting(env?.REDACT_MAX_REDACTIONS,DEFAULT_MAX_REDACTIONS);
  const parseNestedJson = !/^(0|false|no|off)$/i.test(String(env?.REDACT_PARSE_NESTED_JSON ?? "true"));
  const noticeEnabled = !/^(0|false|no|off)$/i.test(String(env?.REDACT_NOTICE_ENABLED ?? "true"));
  const noticePosition = String(env?.REDACT_NOTICE_POSITION ?? "first_user").trim().toLowerCase();
  if (noticePosition !== "first_user" && noticePosition !== "last_user") return jsonError(400,"REDACT_NOTICE_POSITION must be 'first_user' or 'last_user'");
  let manualWords = [];
  if (target.flags.manual && env?.REDACT_MANUAL_WORDS) {
    try {
      manualWords = JSON.parse(env.REDACT_MANUAL_WORDS);
      if (!Array.isArray(manualWords) || manualWords.some(word => typeof word !== "string" || !word.length)) throw new Error();
      manualWords = [...new Set(manualWords)];
    } catch {
      return jsonError(500, "REDACT_MANUAL_WORDS must be a JSON array of non-empty strings");
    }
  }
  const ctx=new RedactionContext({salt:options.salt || getRuntimeSalt(),maxRedactions,parseNestedJson,manualWords});
  const headers=filteredRequestHeaders(request.headers);
  let body;
  if (request.method !== "GET" && request.method !== "HEAD") {
    const bytes=await request.arrayBuffer();
    if (bytes.byteLength > maxBody) return jsonError(413,`Request body exceeds ${maxBody} bytes`);
    const ct=request.headers.get("content-type") || "";
    if (bytes.byteLength && !isJsonContentType(ct)) return jsonError(415,"For safety, request bodies must be JSON so they can be redacted before forwarding");
    if (bytes.byteLength) {
      let data;
      try { data=JSON.parse(new TextDecoder().decode(bytes)); } catch { return jsonError(400,"Invalid JSON request body"); }
      try {
        const protocol=detectProtocol(data,target.upstream,request.headers);
        data=await redactJson(data,ctx,target.flags,protocol);
        injectRedactNotice(data,protocol,{enabled:noticeEnabled,position:noticePosition});
      } catch(e) { if (e instanceof RedactionLimitError) return jsonError(413,e.message); throw e; }
      body=JSON.stringify(data); headers.set("content-type","application/json"); headers.delete("content-length");
    } else body="";
  }

  const fetchImpl=options.fetchImpl || fetch;
  let upstreamResponse;
  try { upstreamResponse=await fetchImpl(target.upstream.toString(),{method:request.method,headers,body,redirect:"manual"}); }
  catch(e) { return jsonError(502,`Upstream fetch failed: ${e?.message || e}`); }

  const responseCt=upstreamResponse.headers.get("content-type") || "";
  if (/text\/event-stream/i.test(responseCt) && upstreamResponse.body) {
    const rh=withCors(upstreamResponse.headers,corsOrigin); rh.delete("content-length"); rh.delete("content-encoding");
    return new Response(restoreSseStream(upstreamResponse.body,ctx),{status:upstreamResponse.status,statusText:upstreamResponse.statusText,headers:rh});
  }
  return restoreNonStreamResponse(upstreamResponse,ctx,corsOrigin);
}

export default { fetch(request, env, ctx) { return handleRequest(request,env); } };

// Same file can be executed directly by Deno Deploy / `deno run --allow-net worker.js`.
if (typeof Deno !== "undefined" && import.meta.main) Deno.serve((request) => {
  let env = {};
  try { env = Deno.env.toObject(); } catch {}
  return handleRequest(request, env);
});
