import fs from "node:fs";
import { isHighEntropyBlock } from "../worker.js";

const words=JSON.parse(fs.readFileSync(new URL("../test/words.json",import.meta.url),"utf8"));
function rng(seed=0x5eed1234){let x=seed>>>0;return()=>((x=(1664525*x+1013904223)>>>0)/2**32);}
function choice(r,a){return a[Math.floor(r()*a.length)];}
function natural(r,n){let s="";while(s.length<n)s+=choice(r,words);return s.slice(0,n);}
function random(r,n,a){let s="";for(let i=0;i<n;i++)s+=a[Math.floor(r()*a.length)];return s;}

let r=rng(), total=0, hits=0;
for(const n of [9,10,11,12,13,16,20,24,32,40,48,64,80,96,128]){
  for(let i=0;i<2000;i++){total++;if(isHighEntropyBlock(natural(r,n)))hits++;}
}
console.log(`natural false positives: ${hits}/${total} = ${(100*hits/total).toFixed(4)}%`);

r=rng(12345);
for(const n of [9,10,11,12,13,16,24,32]){
  for(const [name,a] of [["hex","0123456789abcdef"],["base62","abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"]]){
    let h=0, T=5000;
    for(let i=0;i<T;i++) if(isHighEntropyBlock(random(r,n,a))) h++;
    console.log(`${name.padEnd(6)} length=${String(n).padStart(3)} recall=${(100*h/T).toFixed(2)}%`);
  }
}
