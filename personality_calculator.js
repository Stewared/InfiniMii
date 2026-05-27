var movement=8;
var speech=2;
var expressiveness=7;
var attitude=2;
//[miiMongoObject].tl.personality.[movement]

var personalities=[
    ["Independent | Lone Wolf","Indepedendent | Thinker","Confident | Brainiac","Confident Go-getter"],
    ["Independent | Free Spirit","Independent | Artist","Confident | Designer","Confident | Adventurer"],
    ["Easygoing | Buddy","Easygoing | Dreamer","Outgoing | Charmer","Outgoing | Leader"],
    ["Easygoing | Softie","Easygoing | Optimist","Outgoing | Trendsetter","Outgoing | Entertainer"]
];

movement--;
speech--;
expressiveness--;
attitude--;

if(speech>3) speech++;
if(attitude>3) attitude++;

var x=movement+speech;
var y=expressiveness+attitude;

console.log(`${x} | ${y}`);

console.log(personalities[Math.floor(y/4)][Math.floor(x/4)]);

/*
Male
- Outgoing: Yellow
- Easygoing: Green
- Confident: Blue
- Independent: Teal
Female
- Outgoing: Red young, Yellow adult
- Easygoing: Orange young, Red adult
- Confident: Pink
- Independent: Purple
*/