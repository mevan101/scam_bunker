const R = {
 wrongNumberFix: /\b(wrong number|sorry,? i (think|must have) (texted|messaged|got) the wrong|is this [A-Z][a-z]{1,15}\s*\?)/,
 taskJargon: /\b(product boosting|boost(ing)? (products|orders|merchants?)|app optimi[sz]ation|data optimi[sz]ation|order grabbing|grab orders|double (task|order)s?|combination (task|order)s?|lucky order)\b/i,
 payToWithdraw: /\b(deposit|recharge|top[- ]?up|pay)\b[^.!?\n]{0,50}\b(to|before (you|u) can|in order to|so (you|u) can)\s+(withdraw|unfreeze|unlock|release|cash out)\b|\b(withdrawal|account)\b[^.!?\n]{0,30}\b(frozen|locked|suspended)\b[^.!?\n]{0,60}\b(tax|fee|deposit|margin|insurance|verification)\b/i,
 seedPhrase: /(?<!\b(never|not|don'?t|do not|won'?t|will not|nobody|no one)\b[^.!?\n]{0,25})\b(enter|share|send|provide|type|submit|confirm|validate|sync|import|give)\b[^.!?\n]{0,30}\b(seed|recovery|secret|mnemonic|backup) ?(phrase|words|key)\b/i,
 walletSync: /\b(validate|synchroni[sz]e|sync|rectify|re-?activate|connect) (your )?wallet\b[^.!?\n]{0,40}\b(to (claim|receive|fix|restore|avoid|unlock)|airdrop|reward)\b|\bwallet (validation|synchroni[sz]ation|rectification)\b/i,
 recoveryFirm: /\b(crypto(currency)? (fund |asset )?recovery (law )?(firm|agency|agent|service|specialist)s?|asset recovery (agent|specialist|firm)|(list|database|registry) of (scam |fraud )?victims|recovered (your|the) (stolen|lost|scammed) funds)\b/i,
 hiMum: /\b(hi|hey|hello)\s+(mum|mom|mam|mummy|mommy|dad|daddy)\b[^]{0,120}?\b(new (number|phone|mobile)|lost my phone|broke my phone|phone (is |got )?(broken|smashed|lost)|this is my new)\b/i,
 toll: /\b(unpaid|outstanding|overdue)\s+(toll|parking|traffic|road|congestion)\s+(balance|fee|charge|fine|invoice|bill)s?\b/i,
 parcel: /\b(package|parcel|shipment|delivery)\b[^.!?\n]{0,40}\b(could not be delivered|undeliverable|is on hold|held at (our|the) (depot|warehouse)|address (is )?(incomplete|incorrect|invalid)|redelivery fee)\b/i,
 remote: /\b(install|download|open)\b[^.!?\n]{0,30}\b(rustdesk|ultraviewer|screenconnect|connectwise|quick ?assist|quicksupport|supremo|airdroid|ammyy|anydesk|teamviewer)\b/i,
 kiosk: /\b(bitcoin|crypto(currency)?|btc)\s+(atm|kiosk|machine)s?\b|\b(scan|use) (the|this) qr code\b[^.!?\n]{0,60}\b(deposit|kiosk|atm|machine)\b/i,
 sextortion: /\b(recorded you|hacked (your|ur) (device|phone|computer|camera|webcam)|(intimate|nude|explicit|compromising) (video|photos?|images?|recording)s?)\b[^]{0,200}?\b(bitcoin|btc|crypto|usdt|wallet)\b/i,
 celebInvest: /\b(elon musk|musk|jeff bezos|warren buffett?|bill gates|martin lewis|mark cuban|zuckerberg|cristiano ronaldo)\b[^.!?\n]{0,60}\b(new|secret|revolutionary|his|own|exclusive)\s+(ai |crypto |trading |investment |quantum )?(trading )?(platform|app|system|bot)\b/i,
 guaranteeFix: /\b(guaranteed (returns?|profits?|income|payouts?)|risk[- ]free (investment|returns?|profits?|trading)|double your (money|bitcoin|crypto|investment)|passive income|daily (profit|returns?)|\d{1,4}% (daily |weekly |monthly )?(returns?|profit|roi))\b/i,
};
const T = {
 wrongNumberFix:[['Hello, is this Anna?',1],['Sorry, I think I texted the wrong number',1],['Is this the right place for the meeting?',0],['is this ok?',0]],
 taskJargon:[['Our job is product boosting for merchants, 40 tasks per set',1],['You got a combination order today, big commission',1],['We are hiring for app optimization work',1],['We optimised our app performance',0],['Please review the products in our catalogue',0]],
 payToWithdraw:[['You must deposit 500 USDT to withdraw your profits',1],['Your withdrawal is frozen, pay the 20% tax to release funds',1],['Recharge your account so you can withdraw the commission',1],['You can withdraw cash from any ATM',0],['I will transfer the money to withdraw later from savings',0],['Pay the fee to unlock your account',1]],
 seedPhrase:[['Please enter your 12 word seed phrase to verify',1],['Support: send us your recovery phrase so we can sync',1],['Never share your seed phrase with anyone',0],['We will not ask you to enter your recovery phrase',0],['Write down your recovery phrase and keep it offline',0]],
 walletSync:[['Connect your wallet to claim the airdrop',1],['Wallet validation required within 24h',1],['Connect your wallet to the dapp to view your balance',0]],
 recoveryFirm:[['We are a cryptocurrency recovery law firm working with the FBI',1],['Your name is on a list of scam victims eligible for compensation',1],['Asset recovery specialist can help you',1],['The police recovered the stolen car',0]],
 hiMum:[['Hi Mum, this is my new number, my phone broke',1],['hey dad lost my phone, text me here',1],['Hi mum, see you at dinner',0]],
 toll:[['E-ZPass: You have an unpaid toll balance of $4.15. Pay now',1],['Toll roads are expensive',0]],
 parcel:[['USPS: Your package could not be delivered due to incomplete address',1],['Your parcel is on hold, pay the redelivery fee',1],['The package was delivered to your porch',0]],
 remote:[['Please download AnyDesk so our technician can help',1],['Install RustDesk and tell me the code',1],['I use TeamViewer at work',0]],
 kiosk:[['Withdraw cash and go to the nearest Bitcoin ATM',1],['Scan the QR code at the kiosk to deposit',1],['Scan the QR code to see the menu',0]],
 sextortion:[['I have recorded you through your webcam. Send 1500 USD in bitcoin to this wallet',1],['We have new photos of the trip, I sent them to your wallet app',0],['I hacked your camera and have an explicit video. Pay 0.05 BTC',1]],
 celebInvest:[['Elon Musk reveals his new AI trading platform',1],['Martin Lewis exclusive investment app pays 3000 a day',1],['Elon Musk bought Twitter in 2022',0]],
 guaranteeFix:[['Guaranteed returns of 30% monthly',1],['5% daily returns on your USDT',1],['Satisfaction guaranteed or your money back',0],['Our product has a 10x zoom lens',0]],
};
let fail=0;for(const [k,cases] of Object.entries(T)) for(const [s,exp] of cases){const got=R[k].test(s)?1:0; if(got!==exp){fail++;console.log('FAIL',k,exp,JSON.stringify(s));}}
console.log(fail?fail+' failures':'all pass');
