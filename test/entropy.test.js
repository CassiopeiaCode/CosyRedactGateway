import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { isHighEntropyBlock, entropyThreshold } from "../worker.js";

const words = JSON.parse(fs.readFileSync(new URL("./words.json", import.meta.url), "utf8"));
function rng(seed=0x5eed1234) { let x=seed>>>0; return () => ((x=(1664525*x+1013904223)>>>0)/2**32); }
function choice(r,a){ return a[Math.floor(r()*a.length)]; }
function naturalBlock(r,n){ let s=""; while(s.length<n) s += choice(r,words); return s.slice(0,n); }
function randomBlock(r,n,alphabet){ let s=""; for(let i=0;i<n;i++) s+=alphabet[Math.floor(r()*alphabet.length)]; return s; }

test("entropy threshold decreases with length and only applies above 8 chars", () => {
  assert.equal(entropyThreshold(8), Infinity);
  let prev=Infinity;
  for (let n=9;n<=128;n++) { const t=entropyThreshold(n); assert(t<=prev+1e-9); prev=t; }
});

test("Monte Carlo: <1% held-out natural concatenations are classified high entropy", () => {
  const r=rng();
  let total=0, hits=0;
  for (const n of [9,10,11,12,13,16,20,24,32,40,48,64,80,96,128]) {
    for(let i=0;i<2000;i++){ total++; if(isHighEntropyBlock(naturalBlock(r,n))) hits++; }
  }
  const rate=hits/total;
  assert(rate < 0.01, `natural-language false-positive rate ${rate}`);
});

test("random secret recall is high for realistic alphanumeric/hex blocks", () => {
  const r=rng(12345); const alphabets=["0123456789abcdef","abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"];
  for (const [n,minRate] of [[12,0.94],[16,0.98],[24,0.995],[32,0.995]]) {
    for (const alphabet of alphabets) {
      let hits=0, total=2000;
      for(let i=0;i<total;i++) if(isHighEntropyBlock(randomBlock(r,n,alphabet))) hits++;
      assert(hits/total >= minRate, `${n} ${alphabet.length} recall=${hits/total}`);
    }
  }
});

test("obviously repetitive strings are not high entropy", () => {
  for (const s of ["aaaaaaaaaaaa", "abcabcabcabc", "111111111111", "zzzzzzzzzzzzzzzz"]) assert.equal(isHighEntropyBlock(s),false,s);
});
