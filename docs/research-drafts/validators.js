// Zero-dependency, synchronous validators proposed for public/scam.js
function sha256(bytes){const K=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
 const l=bytes.length,n=((l+9+63)>>6)<<6,m=new Uint8Array(n);m.set(bytes);m[l]=0x80;const dv=new DataView(m.buffer);dv.setUint32(n-4,l*8);dv.setUint32(n-8,Math.floor(l/0x20000000));
 let h=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];const w=new Uint32Array(64);const r=(x,k)=>(x>>>k)|(x<<(32-k));
 for(let o=0;o<n;o+=64){for(let i=0;i<16;i++)w[i]=dv.getUint32(o+i*4);for(let i=16;i<64;i++){const s0=r(w[i-15],7)^r(w[i-15],18)^(w[i-15]>>>3),s1=r(w[i-2],17)^r(w[i-2],19)^(w[i-2]>>>10);w[i]=(w[i-16]+s0+w[i-7]+s1)|0;}
  let [a,b,c,d,e,f,g,hh]=h;for(let i=0;i<64;i++){const t1=(hh+(r(e,6)^r(e,11)^r(e,25))+((e&f)^(~e&g))+K[i]+w[i])|0,t2=((r(a,2)^r(a,13)^r(a,22))+((a&b)^(a&c)^(b&c)))|0;hh=g;g=f;f=e;e=(d+t1)|0;d=c;c=b;b=a;a=(t1+t2)|0;}
  h=h.map((v,i)=>(v+[a,b,c,d,e,f,g,hh][i])|0);}
 const out=new Uint8Array(32);h.forEach((v,i)=>new DataView(out.buffer).setUint32(i*4,v));return out;}
const B58='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function b58decode(s){let bytes=[0];for(const ch of s){const v=B58.indexOf(ch);if(v<0)return null;let carry=v;for(let i=0;i<bytes.length;i++){carry+=bytes[i]*58;bytes[i]=carry&0xff;carry>>=8;}while(carry){bytes.push(carry&0xff);carry>>=8;}}for(const ch of s){if(ch==='1')bytes.push(0);else break;}return new Uint8Array(bytes.reverse());}
function base58checkOk(s){const b=b58decode(s);if(!b||b.length<5)return false;const p=b.slice(0,-4),c=b.slice(-4),h=sha256(sha256(p));return c.every((x,i)=>x===h[i]);}
// Bech32/Bech32m (BIP-173/350) checksum for bc1 addresses
function bech32Ok(addr){const C='qpzry9x8gf2tvdw0s3jn54khce6mua7l';const s=addr.toLowerCase();if(s!==addr&&addr.toUpperCase()!==addr)return false;const p=s.lastIndexOf('1');if(p<1||p+7>s.length)return false;const hrp=s.slice(0,p),data=[...s.slice(p+1)].map(c=>C.indexOf(c));if(data.some(x=>x<0))return false;
 const G=[0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3];let chk=1;const pm=v=>{const t=chk>>25;chk=((chk&0x1ffffff)<<5)^v;for(let i=0;i<5;i++)if((t>>i)&1)chk^=G[i];};
 for(const c of hrp)pm(c.charCodeAt(0)>>5);pm(0);for(const c of hrp)pm(c.charCodeAt(0)&31);for(const d of data)pm(d);return chk===1||chk===0x2bc830a3;}
// EIP-55: mixed-case addresses carry a checksum; all-lower/all-upper do not (accept, but mark unchecked). Needs keccak256 — out of scope for zero-dep; accept by format.
function walletOk(chain,a){if(chain==='Bitcoin')return a.startsWith('bc1')?bech32Ok(a):base58checkOk(a);if(chain.startsWith('Tron'))return base58checkOk(a)&&b58decode(a)[0]===0x41;return true;}
// Phone guard: reject dates/times/IDs that the current regex accepts
function phoneOk(raw){const d=raw.replace(/\D/g,'');if(d.length<9||d.length>15)return false;
 if(/^(19|20)\d{2}[-\/. ]\d{1,2}[-\/. ]\d{1,2}/.test(raw.trim()))return false; // ISO-like date
 if(/^\d{1,2}[-\/.]\d{1,2}[-\/.](19|20)?\d{2}\b/.test(raw.trim()))return false; // dd/mm/yyyy
 if(/^(\d)\1+$/.test(d)||'01234567890123456789'.includes(d))return false; // 1111111111, 1234567890
 return /^\+/.test(raw.trim())||/^0/.test(d)||/[\s().-]/.test(raw);}
module.exports={base58checkOk,bech32Ok,walletOk,phoneOk};
if(require.main===module){
 const t=[['Bitcoin','1BoatSLRHtKNngkdXEeobR76b53LETtpyT',true],['Bitcoin','3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy',true],['Bitcoin','3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLz',false],['Bitcoin','bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq',true],['Bitcoin','bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdx',false],['Bitcoin','1wiz18xYmhRX6xStj2b9t1rwWX4GKUgpv',true],
  ['Tron (USDT-TRC20)','TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t',true],['Tron (USDT-TRC20)','TNXoiAJ3dct8Fjg4M9fkLFh9S2v9TXc32G',true],['Tron (USDT-TRC20)','TJYeasTPa6gpEEfYqCP9sMBc7NJqKPDJvT',false]];
 for(const [c,a,e] of t){const g=walletOk(c,a);console.log(g===e?'ok  ':'FAIL',c,a,g);}
 for(const [p,e] of [['+44 7700 900123',true],['(415) 555-0132',true],['07700 900123',true],['2024-11-26 10',false],['2024 11 26 1030',false],['26/11/2024 1030',false],['1234567890',false],['+1 202-555-0187',true]]){const g=phoneOk(p);console.log(g===e?'ok  ':'FAIL','phone',p,g);}
}
