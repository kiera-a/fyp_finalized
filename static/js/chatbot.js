const toggle=document.createElement("button");
toggle.id="chat-toggle";
toggle.innerHTML="🤖";

document.body.appendChild(toggle);

const chat=document.createElement("div");

chat.id="chat-window";

chat.innerHTML=`
<div id="chat-header">
PrivacyGuardian AI
</div>

<div id="chat-body">
<div class="message bot">
<span>
👋 Hi!

I'm your AI Privacy Assistant.

Ask me anything about:

• OCR

• PDPA

• Privacy

• Your uploaded document
</span>
</div>
</div>

<div id="chat-input-area">
<input id="chat-input"
placeholder="Ask something...">

<button id="send-btn">
➜
</button>

</div>
`;

document.body.appendChild(chat);

toggle.onclick=()=>{

chat.style.display=

chat.style.display==="block"

?

"none"

:

"block";

};

async function sendMessage(){

const input=document.getElementById("chat-input");

const msg=input.value.trim();

if(msg==="") return;

const body=document.getElementById("chat-body");

body.innerHTML+=`

<div class="message user">

<span>${msg}</span>

</div>

`;

input.value="";

body.innerHTML+=`

<div class="message bot" id="typing">

<span>

Thinking...

</span>

</div>

`;

body.scrollTop=body.scrollHeight;

const response=await fetch("/chat",{

method:"POST",

headers:{

"Content-Type":"application/json"

},

body:JSON.stringify({

message:msg

})

});

const data=await response.json();

document.getElementById("typing").remove();

const html = marked.parse(data.reply);

body.innerHTML += `
<div class="message bot">
    <div class="bot-content">
        ${html}
    </div>
</div>
`;

body.scrollTop=body.scrollHeight;

}

document

.getElementById("send-btn")

.onclick=sendMessage;

document

.getElementById("chat-input")

.addEventListener("keypress",function(e){

if(e.key==="Enter")

sendMessage();

});