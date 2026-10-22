/* ABI NEXUS storage extension — analysis, not Solidity source reconstruction */
(() => {
"use strict";
const $ = id => document.getElementById(id);
const state = {report:null, mappingHints:[], lastBytecode:""};
const SAMPLE_PACKED_MAPPING = "0x60005460ff165060005460a01c600116506001600052600260205260406000205400";
const SAMPLE_GETTERS = [
 {type:"function",name:"balances",stateMutability:"view",inputs:[{name:"who",type:"address"}],outputs:[{name:"",type:"uint256"}]},
 {type:"function",name:"positions",stateMutability:"view",inputs:[{name:"owner",type:"address"},{name:"index",type:"uint256"}],outputs:[{name:"liquidity",type:"uint128"},{name:"active",type:"bool"}]}
];
const HOP = {0x00:"STOP",0x01:"ADD",0x03:"SUB",0x14:"EQ",0x15:"ISZERO",0x16:"AND",0x17:"OR",0x18:"XOR",0x19:"NOT",0x1b:"SHL",0x1c:"SHR",0x1d:"SAR",0x20:"KECCAK256",0x35:"CALLDATALOAD",0x50:"POP",0x51:"MLOAD",0x52:"MSTORE",0x53:"MSTORE8",0x54:"SLOAD",0x55:"SSTORE",0x56:"JUMP",0x57:"JUMPI",0x5b:"JUMPDEST",0x5c:"TLOAD",0x5d:"TSTORE",0x5f:"PUSH0",0xf3:"RETURN",0xfd:"REVERT"};
const asHex = n => "0x"+BigInt(n).toString(16);
const data = (value)=>JSON.stringify(value,(k,v)=>typeof v==="bigint"?String(v):v,2);
function notice(message,bad=false){const el=$("toast");el.textContent=message;el.classList.toggle("error",bad);el.classList.add("show");setTimeout(()=>el.classList.remove("show"),3800)}
function node(tag,cls,content){const n=document.createElement(tag);if(cls)n.className=cls;if(content!==undefined)n.textContent=String(content);return n}
function empty(el){el.replaceChildren();el.classList.remove("empty-result")}
function card(root,title,tag,body){const item=node("article","entry");const top=node("div","entry-top");top.append(node("strong","entry-title",title),node("span","tag",tag));item.append(top);for(const line of body){item.append(node("div","entry-detail",line))}root.append(item);return item}
function summary(root,title,message){const d=node("div","result-summary");d.append(node("strong","",title),node("div","",message));root.append(d)}
function getHex(){const h=$("storage-bytecode").value.trim();if(!/^0x(?:[0-9a-fA-F]{2})+$/.test(h))throw Error("Bytecode cần định dạng 0x + chuỗi hex có độ dài chẵn.");if(h.length>350002)throw Error("Đầu vào giới hạn 175 KB.");return h.toLowerCase()}
function parse(hex){const h=hex.slice(2);const result=[];for(let pc=0;pc<h.length/2;){const op=parseInt(h.slice(pc*2,pc*2+2),16);const width=op>=0x60&&op<=0x7f?op-0x5f:0;const start=pc;const immediate=h.slice((pc+1)*2,(pc+1+width)*2);if(immediate.length!==width*2)throw Error("Bytecode kết thúc giữa PUSH instruction tại PC "+pc);result.push({pc,op,name:op>=0x60&&op<=0x7f?"PUSH"+width:op>=0x80&&op<=0x8f?"DUP"+(op-0x7f):op>=0x90&&op<=0x9f?"SWAP"+(op-0x8f):HOP[op]||"OP_"+op.toString(16),value:immediate?"0x"+immediate:null});pc=start+1+width;if(result.length>100000)throw Error("Số opcode vượt 100.000.")}return result}
function bitMaskWidth(n){if(typeof n!=="bigint"||n<=0n)return null;const w=n.toString(2).length;if(w>256||w%8!==0||n!==((1n<<BigInt(w))-1n))return null;return w/8}
const unknown=()=>({kind:"unknown"});
function known(item){return item&&item.kind==="constant"}
function pop(stack){return stack.pop()||unknown()}
function candidateType(key){
 if(!key)return "unknown";
 if(key.kind==="maskedCalldata"&&key.width===20)return "address hoặc uint160 (chưa xác minh)";
 if(key.kind==="calldata")return "unknown (calldata)";
 return "unknown";
}
function staticAnalyze(hex){
 const ops=parse(hex),stack=[],mem=new Map(),loads=[],fields=[],mapAccess=[],slotAccess=[],warnings=[];
 const word=n=>known(n)?asHex(n.value):null;
 const pathSlot=slot=>slot&&slot.kind==="constant"?asHex(slot.value):slot&&slot.kind==="mapping"?slot.baseSlot||"dynamic":"unknown";
 function maskedExpr(a,b,pc){
   const mask=known(a)?a:known(b)?b:null,source=mask===a?b:a;
   if(!mask)return unknown();
   const byteWidth=bitMaskWidth(mask.value);
   if(source.kind==="calldata"&&byteWidth)return {kind:"maskedCalldata",width:byteWidth,pc};
   if(source.kind==="load"||source.kind==="extracted"){
     const offset=source.offset||0;
     if(byteWidth&&offset+byteWidth<=32){
       fields.push({slot:source.slot,offset,width:byteWidth,pc,evidence:["SLOAD",offset?"SHR "+(offset*8):"SHR 0","AND "+asHex(mask.value)],confidence:"heuristic",typeHint:byteWidth===1?"uint8/bool/bytes1":byteWidth===20?"address/uint160/bytes20":"uint"+(byteWidth*8)+"/bytes"+byteWidth});
       return {kind:"extracted",slot:source.slot,offset,width:byteWidth}
     }
   }
   return unknown();
 }
 for(const op of ops){
   const pc=op.pc,name=op.name;
   if(name==="JUMPDEST"||name==="JUMP"||name==="JUMPI"){stack.length=0;mem.clear();continue}
   if(name.startsWith("PUSH")){stack.push({kind:"constant",value:name==="PUSH0"?0n:BigInt(op.value),pc});continue}
   if(name.startsWith("DUP")){const n=Number(name.slice(3));stack.push(stack[stack.length-n]||unknown());continue}
   if(name.startsWith("SWAP")){const n=Number(name.slice(4));const index=stack.length-1-n;if(index>=0){const a=stack.length-1;[stack[a],stack[index]]=[stack[index],stack[a]]}else stack.length=0;continue}
   if(name==="POP"){pop(stack);continue}
   if(name==="CALLDATALOAD"){const src=pop(stack);stack.push({kind:"calldata",source:word(src)||"dynamic",pc});continue}
   if(name==="SLOAD"||name==="TLOAD"){const index=pop(stack),slot=pathSlot(index);const loc=name==="TLOAD"?"transient":"persistent";const record={operation:name,slot,pc,location:loc,derivedMapping:index.kind==="mapping"};loads.push(record);slotAccess.push(record);if(index.kind==="mapping")mapAccess.push({slot:index.baseSlot||"unknown",depth:index.depth||1,keys:index.keys||[],pc,evidence:index.evidence||[],op:name,confidence:"symbolic-stack-path"});stack.push({kind:"load",slot,offset:0,pc});continue}
   if(name==="SSTORE"||name==="TSTORE"){const index=pop(stack);pop(stack);const slot=pathSlot(index),record={operation:name,slot,pc,location:name==="TSTORE"?"transient":"persistent",derivedMapping:index.kind==="mapping"};slotAccess.push(record);if(index.kind==="mapping")mapAccess.push({slot:index.baseSlot||"unknown",depth:index.depth||1,keys:index.keys||[],pc,evidence:index.evidence||[],op:name,confidence:"symbolic-stack-path"});continue}
   if(name==="MSTORE"){const offset=pop(stack),value=pop(stack);if(known(offset)&&offset.value<=4096n)mem.set(Number(offset.value),value);else mem.clear();continue}
   if(name==="MSTORE8"){const offset=pop(stack);pop(stack);mem.delete(Number(known(offset)?offset.value:-1n));continue}
   if(name==="MLOAD"){const offset=pop(stack);stack.push(known(offset)?mem.get(Number(offset.value))||unknown():unknown());continue}
   if(name==="KECCAK256"){const offset=pop(stack),size=pop(stack);if(known(offset)&&known(size)&&size.value===64n){const off=Number(offset.value),key=mem.get(off),base=mem.get(off+32);if(base&&(base.kind==="constant"||base.kind==="mapping")){const root=base.kind==="constant"?asHex(base.value):base.baseSlot;const keys=(base.keys||[]).concat([{typeHint:candidateType(key),source:key&&key.kind||"unknown"}]);stack.push({kind:"mapping",baseSlot:root,depth:keys.length,keys,evidence:["MSTORE @ "+off,"MSTORE @ "+(off+32),"KECCAK256 @ "+pc],pc});continue}}stack.push(unknown());continue}
   if(name==="SHR"||name==="SAR"){const shift=pop(stack),operand=pop(stack);if(known(shift)&&shift.value>=0n&&shift.value<=248n&&shift.value%8n===0n&&(operand.kind==="load"||operand.kind==="extracted"))stack.push({...operand,kind:"extracted",offset:(operand.offset||0)+Number(shift.value/8n)});else stack.push(unknown());continue}
   if(name==="AND"){const a=pop(stack),b=pop(stack);stack.push(maskedExpr(a,b,pc));continue}
   if(name==="ISZERO"||name==="NOT"){pop(stack);stack.push(unknown());continue}
   if(["EQ","ADD","SUB","OR","XOR","SHL"].includes(name)){pop(stack);pop(stack);stack.push(unknown());continue}
   if(["STOP","RETURN","REVERT"].includes(name)){stack.length=0;mem.clear();continue}
   /* Unknown stack effect: intentionally discard state instead of inventing paths */
   stack.length=0;mem.clear();
 }
 const slotMap=new Map();
 for(const access of slotAccess){const key=access.location+":"+access.slot;if(!slotMap.has(key))slotMap.set(key,{slot:access.slot,location:access.location,accesses:[],fields:[]});slotMap.get(key).accesses.push({operation:access.operation,pc:access.pc})}
 for(const fld of fields){const key="persistent:"+fld.slot;if(!slotMap.has(key))slotMap.set(key,{slot:fld.slot,location:"persistent",accesses:[],fields:[]});const row=slotMap.get(key);if(!row.fields.some(x=>x.offset===fld.offset&&x.width===fld.width))row.fields.push(fld)}
 if(ops.some(x=>x.name==="OP_5e"))warnings.push("MCOPY có thể ảnh hưởng bộ theo dõi memory; phân tích cục bộ chưa xử lý.");
 warnings.push("Quét tuyến tính cục bộ không theo CFG hoặc trace; bỏ qua nhánh và nhiều opcode để tránh suy luận không có căn cứ.");
 const mappingMap=new Map();
 for(const m of mapAccess){const k=m.slot+":"+m.depth;if(!mappingMap.has(k))mappingMap.set(k,{slot:m.slot,depth:m.depth,keys:m.keys,valueType:"unknown",confidence:"candidate",evidence:m.evidence,accesses:[]});mappingMap.get(k).accesses.push({operation:m.op,pc:m.pc})}
 return {engine:"local-heuristic",status:"candidate",analysisType:"symbolic-linear-scan",bytes:(hex.length-2)/2,instructions:ops.length,slots:[...slotMap.values()].slice(0,150),mappings:[...mappingMap.values()].slice(0,100),warnings,backendVerified:false};
}
function paintBar(root,slot){const bar=node("div","slot-bar");const segments=(slot.fields||[]).filter(x=>Number.isInteger(x.offset)&&Number.isInteger(x.width)&&x.offset>=0&&x.offset+x.width<=32).sort((a,b)=>a.offset-b.offset);
 let cursor=0;
 for(const f of segments){if(f.offset<cursor){const conf=node("span","slot-overlap","TRÙNG VÙNG TRUY CẬP · CHƯA KẾT LUẬN COLLISION");root.append(conf);continue}if(f.offset>cursor){const blank=node("div","slot-empty");blank.style.flex=String(f.offset-cursor);bar.append(blank)}const part=node("div","slot-field",f.name||f.typeHint||"field");part.style.flex=String(f.width);part.title="Byte "+f.offset+"–"+(f.offset+f.width-1);bar.append(part);cursor=f.offset+f.width}
 if(cursor<32){const blank=node("div","slot-empty");blank.style.flex=String(32-cursor);bar.append(blank)}root.append(bar)}
function renderStorage(){
 const r=state.report,root=$("storage-result");empty(root);
 if(!r){root.classList.add("empty-result");root.textContent="Chưa có kết quả.";return}
 $("storage-count").textContent=r.slots.length;
 $("packed-count").textContent=r.slots.filter(x=>(x.fields||[]).length).length;
 $("mapping-count").textContent=r.mappings.length;
 const deep=r.engine==="gigahorse-dyels";
 $("storage-mode").textContent=deep?"DYELS · ENGINE RESULT":"LOCAL · HEURISTIC";
 $("storage-mode").classList.toggle("engine-ok",deep);
 summary(root,deep?"Đã chạy Gigahorse–DYELS":"Ứng viên cấu trúc từ quét bytecode","Engine: "+r.engine+". "+(deep?"Các quan hệ Datalog được gắn kèm provenance; kiểu suy luận có thể chưa đầy đủ.":"Không có xác minh CFG; kiểu từ opcode có thể mơ hồ."));
 if(r.slots.length===0)card(root,"Chưa nhận diện được slot","NO EVIDENCE",["Không suy ra biến khi dữ liệu không đủ. Hãy chạy DYELS backend để tăng phạm vi phân tích."]);
 for(const slot of r.slots.slice(0,120)){
   const s=card(root,"Slot "+(slot.slot||"?"),slot.location||"STORAGE",[(slot.accesses||[]).length+" thao tác truy cập; "+(slot.fields||[]).length+" trường ứng viên"]);
   if(slot.fields&&slot.fields.length)paintBar(s,slot);
   for(const f of (slot.fields||[]).slice(0,20)){s.append(node("div","entry-code","Byte "+(f.offset??"?")+"–"+(typeof f.offset==="number"&&typeof f.width==="number"?f.offset+f.width-1:"?")+" · "+(f.type||f.typeHint||"unknown")+" · "+(f.confidence||"candidate")))}
   for(const op of (slot.accesses||[]).slice(0,8)){s.append(node("div","entry-detail",(op.operation||"access")+" @ "+(op.pc??op.stmt??"?")))}
 }
 if(r.mappings.length){const jump=node("button","btn secondary full","⊞ Xem cây mapping "+r.mappings.length+" cấu trúc →");jump.addEventListener("click",()=>document.querySelector('[data-go="mapping"]').click());root.append(jump)}
 for(const w of (r.warnings||[]).slice(0,10))card(root,"Lưu ý & giới hạn","WARNING",[w]);
 if(r.relations&&Object.keys(r.relations).length){const count=Object.entries(r.relations).map(([k,v])=>k+"="+v.length).join("; ");card(root,"Quan hệ Datalog","PROVENANCE",[count])}
 renderMapping();
}
function download(obj,filename){if(!obj){notice("Chưa có dữ liệu xuất.",true);return}const url=URL.createObjectURL(new Blob([data(obj)],{type:"application/json"}));const a=node("a");a.href=url;a.download=filename;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1200)}
function analyzeLocal(){try{const hex=getHex();state.lastBytecode=hex;state.report=staticAnalyze(hex);renderStorage();notice("Quét xong. Các kết quả cục bộ đều là ứng viên chưa xác minh.");}catch(err){notice("Storage: "+err.message,true)}}
function endpoint(){const raw=$("storage-api").value.trim().replace(/\/+$/,"");if(!raw)throw Error("Chưa nhập URL backend DYELS.");let url;try{url=new URL(raw)}catch(err){throw Error("URL backend không hợp lệ.")}if(url.protocol!=="https:"&&!(url.protocol==="http:"&&["localhost","127.0.0.1"].includes(url.hostname)))throw Error("Backend phải HTTPS hoặc localhost.");if(url.username||url.password||url.search||url.hash)throw Error("URL backend không được chứa mật khẩu, query hoặc fragment.");return url.origin+url.pathname.replace(/\/+$/,"")}
const authHeaders=()=>{const h={"Content-Type":"application/json"};if($("storage-token").value)h.Authorization="Bearer "+$("storage-token").value;return h};
async function health(){try{const url=endpoint();const ctl=new AbortController();const t=setTimeout(()=>ctl.abort(),8500);try{const r=await fetch(url+"/api/health",{signal:ctl.signal,cache:"no-store"});if(!r.ok)throw Error("HTTP "+r.status);const j=await r.json();$("storage-health").textContent=(j.dyelsReady?"DYELS READY":"DYELS NOT CONFIGURED")+" · "+(j.engine||"backend");notice(j.dyelsReady?"Backend DYELS phản hồi sẵn sàng.":"Backend phản hồi nhưng chưa có Gigahorse/DYELS.");}finally{clearTimeout(t)}}catch(err){$("storage-health").textContent="Không kết nối được backend";notice("Backend: "+err.message,true)}}
async function analyzeDeep(){const button=$("storage-deep");try{const url=endpoint(),hex=getHex();button.disabled=true;button.textContent="Đang phân tích DYELS…";const ctl=new AbortController();const timer=setTimeout(()=>ctl.abort(),150000);try{const response=await fetch(url+"/api/analyze",{method:"POST",headers:authHeaders(),body:data({bytecode:hex}),signal:ctl.signal});let report;try{report=await response.json()}catch(err){throw Error("Backend không trả JSON hợp lệ.")}if(!response.ok)throw Error(report.detail||report.error||"HTTP "+response.status);if(report.engine!=="gigahorse-dyels"||!Array.isArray(report.slots)||!Array.isArray(report.mappings))throw Error("Schema backend không đúng.");state.report=report;state.lastBytecode=hex;renderStorage();notice("DYELS đã trả kết quả có chứng cứ. Không suy diễn nếu kiểu chưa xác định.");}finally{clearTimeout(timer)}}catch(err){notice("DYELS: "+(err.name==="AbortError"?"Hết thời gian.":err.message),true)}finally{button.disabled=false;button.textContent="◈ Chạy phục hồi DYELS"}}
function getterHints(){try{const raw=$("mapping-abi").value.trim();if(!raw)throw Error("Hãy nhập ABI JSON.");let abi=JSON.parse(raw);if(abi.abi)abi=abi.abi;if(!Array.isArray(abi)||abi.length>1000)throw Error("ABI cần là mảng tối đa 1.000 phần tử.");const hints=[];for(const f of abi){if(f.type!=="function"||!Array.isArray(f.inputs)||!Array.isArray(f.outputs)||f.inputs.length===0)continue;if(!["view","pure"].includes(f.stateMutability))continue;const keys=f.inputs.map(p=>p.type||"unknown"),values=f.outputs.map(p=>p.type||"unknown");if(!keys.every(x=>typeof x==="string"))continue;hints.push({name:f.name||"unknown",keys,values,confidence:"ABI-interface-only",warning:"Hàm view có tham số không chứng minh một mapping; cần ghép provenance storage từ DYELS."})}state.mappingHints=hints;renderMapping();notice("Đã nhận "+hints.length+" ứng viên getter ABI; chưa được xác nhận là mapping.");}catch(err){notice("Mapping: "+err.message,true)}}
function renderMapping(){const root=$("mapping-result");empty(root);const mappings=state.report&&state.report.mappings||[];if(mappings.length===0&&state.mappingHints.length===0){root.classList.add("empty-result");root.textContent="Chưa có mapping được suy luận. Chạy DYELS backend hoặc nhập ABI getter để bổ sung ứng viên.";return}
 const deep=state.report&&state.report.engine==="gigahorse-dyels";
 summary(root,deep?"Mapping từ phân tích Datalog":"Mapping hypotheses","Không đoán key/value từ riêng KECCAK256. Mọi kiểu chưa có chứng cứ được giữ 'unknown'.");
 for(const m of mappings.slice(0,100)){const roots=(m.keys||[]);const item=card(root,"Mapping @ "+(m.slot||"unknown"),deep?"DYELS STRUCTURE":"UNVERIFIED",["Độ sâu: "+(m.depth||roots.length||1),"Kiểu giá trị: "+(m.valueType||"unknown"),"Độ chắc chắn: "+(m.confidence||"candidate")]);const path=node("div","mapping-path");path.append(node("span","mapping-node","slot "+(m.slot||"?")));for(let i=0;i<Math.max(roots.length,m.depth||0);i++){const key=roots[i]||{};path.append(node("span","mapping-arrow","→"),node("span","mapping-node",(key.type||key.typeHint||"unknown")+" [key "+(i+1)+"]"))}path.append(node("span","mapping-arrow","→"),node("span","mapping-node value",m.valueType||"unknown"));item.append(path);for(const ev of (m.evidence||[]).slice(0,8))item.append(node("div","entry-detail","Evidence: "+(typeof ev==="string"?ev:JSON.stringify(ev))))}
 for(const hint of state.mappingHints){card(root,"ABI getter · "+hint.name,"ABI HINT",["Input types: "+hint.keys.join(" → "),"Output types: "+hint.values.join(", "),"Chưa xác minh quan hệ với storage mapping."])}
}
$("storage-local").addEventListener("click",analyzeLocal);
$("storage-deep").addEventListener("click",analyzeDeep);
$("storage-health-check").addEventListener("click",health);
$("storage-sample").addEventListener("click",()=>{$("storage-bytecode").value=SAMPLE_PACKED_MAPPING;notice("Đã nạp bytecode mẫu mô phỏng packed read và mapping access.");});
$("storage-copy").addEventListener("click",()=>{const src=$("bytecode-input").value.trim();if(!src){notice("Bytecode Explorer chưa có bytecode.",true);return}$("storage-bytecode").value=src;notice("Đã lấy bytecode từ Bytecode Explorer.");});
$("storage-export").addEventListener("click",()=>download(state.report,"abi-nexus-storage.json"));
$("mapping-export").addEventListener("click",()=>download({analysis:state.report&&state.report.mappings||[],abiGetterCandidates:state.mappingHints},"abi-nexus-mapping.json"));
$("mapping-example").addEventListener("click",()=>{$("mapping-abi").value=data(SAMPLE_GETTERS);notice("Đã nạp ví dụ getter; hãy kiểm tra độ chắc chắn trong kết quả.");});
$("mapping-hints").addEventListener("click",getterHints);
})();
