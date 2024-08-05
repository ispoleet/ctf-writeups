/**
 * Run this code inside Chrome's console.
 */ 
// Copy class from the challenge as-it-is.
class _0x36ee9a_ {
  constructor(p_elementName, p_width, p_height, p_vertexShader, p_fragmentShader, p_someBoolean) {
    this.canvas = document.getElementById(p_elementName);
    if (p_width != 0 && p_height != 0) {
      this.canvas.width = p_width;
      this.canvas.height = p_height;
    } else {
      this.canvas.width = window.innerWidth;
      this.canvas.height = window.innerHeight;
    }
    this.w = this.canvas.width;
    this.h = this.canvas.height;
    this.d = [4, 20, 23, 13, 11, 0, 15, 1, 14, 21, 9, 19, 8, 3, 17, 24, 16, 6, 22, 10, 7, 18, 2, 5, 12];
    this.timeLoad = performance.now();
    this.gl = this.canvas.getContext("webgl2");
    this.gl.getExtension("EXT_color_buffer_float");
    this.v_shader = this.create_shader(p_vertexShader, "OuO"); // VERTEX_SHADER
    this.f_shader = this.create_shader(p_fragmentShader, ">w<"); // FRAGMENT_SHADER
    this.prg = this.create_program(this.v_shader, this.f_shader);
    let _0x579165 = this;
    function _0x52ad9c() {
      _0x579165.render();
      _0x579165.animationFrameRequest = window.requestAnimationFrame(_0x52ad9c);
    }
    if (p_someBoolean) {
      _0x52ad9c();
    }
    return this;
  }

  ["wtf"](p1, p2, p3) {
    this.gl.clearColor(0, 0, 0, 1);
    this.gl.clearDepth(1);
    this.gl.clear(this.gl.COLOR_BUFFER_BIT | this.gl.DEPTH_BUFFER_BIT);
    const _0x4b856b = this.gl.getAttribLocation(this.prg, "position");
    const _0x413a4a = [
      -1, -1, (p1 % 1 + this.d[~~p1]) / 25, 
      -1,  1, (p2 % 1 + this.d[~~p2]) / 25, 
       1,  1, (p2 % 1 + this.d[~~p2]) / 25,

      -1, -1, (p1 % 1 + this.d[~~p1]) / 25,   
       1,  1, (p2 % 1 + this.d[~~p2]) / 25,
       1, -1, (p1 % 1 + this.d[~~p1]) / 25
    ];

    const _0x3e2e26 = this.create_vbo(_0x413a4a);
    this.gl.bindBuffer(this.gl.ARRAY_BUFFER, _0x3e2e26);
    this.gl.enableVertexAttribArray(_0x4b856b);
    this.gl.vertexAttribPointer(_0x4b856b, 3, this.gl.FLOAT, false, 0, 0);
    this.gl.useProgram(this.prg);
    this.gl.drawArrays(this.gl.TRIANGLES, 0, 6);
    this.gl.flush();

    const _0x2fa9a7 = new Uint8Array(4);
    this.gl.readPixels(
      this.w / 2,
      (p3 % 1 + this.d[~~p3]) * this.h / 25,
      1,
      1, this.gl.RGBA, this.gl.UNSIGNED_BYTE, _0x2fa9a7);
    let _0x511406 = new Float32Array(_0x2fa9a7.buffer);
    return _0x511406[0].toFixed(15);
  }
  ["gtfo"](_0x226eef, _0x4ab524, _0x6b804d, _0x3e3cf3, _0x5cd04f) {
    this.gl.clearColor(0, 0, 0, 1);
    this.gl.clearDepth(1);
    this.gl.clear(this.gl.COLOR_BUFFER_BIT | this.gl.DEPTH_BUFFER_BIT);
    const _0x16760a = this.gl.getAttribLocation(this.prg, "position");
    const _0x13e5e0 = [-1, -1, (_0x226eef % 1 + this.d[~~_0x226eef]) / 25, 3, -1, (_0x4ab524 % 1 + this.d[~~_0x4ab524]) / 25, -1, 3, (_0x6b804d % 1 + this.d[~~_0x6b804d]) / 25];
    const _0x49be08 = this.create_vbo(_0x13e5e0);
    this.gl.bindBuffer(this.gl.ARRAY_BUFFER, _0x49be08);
    this.gl.enableVertexAttribArray(_0x16760a);
    this.gl.vertexAttribPointer(_0x16760a, 3, this.gl.FLOAT, false, 0, 0);
    this.gl.useProgram(this.prg);
    this.gl.drawArrays(this.gl.TRIANGLES, 0, 3);
    this.gl.flush();
    const _0x3da8ae = new Uint8Array(4);
    this.gl.readPixels((_0x3e3cf3 % 1 + this.d[~~_0x3e3cf3]) * this.w / 25, (_0x5cd04f % 1 + this.d[~~_0x5cd04f]) * this.h / 25, 1, 1, this.gl.RGBA, this.gl.UNSIGNED_BYTE, _0x3da8ae);
    let _0x2e76ac = new Float32Array(_0x3da8ae.buffer);
    return _0x2e76ac[0].toFixed(15);
  }
  ["render"]() {
    this.gl.clearColor(0, 0, 0, 1);
    this.gl.clearDepth(1);
    this.gl.clear(this.gl.COLOR_BUFFER_BIT | this.gl.DEPTH_BUFFER_BIT);
    let _0x39f658 = performance.now();
    this.timeDelta = (_0x39f658 - this.timePrev) / 1e3;
    this.timePrev = _0x39f658;
    const _0x18111e = new Array(2);
    _0x18111e[0] = this.gl.getAttribLocation(this.prg, "position");
    const _0x15ddf2 = new Array(2);
    _0x15ddf2[0] = 3;
    _0x15ddf2[1] = 4;
    const _0x2626af = [3, 8, 0, 7, -3, 5, 3, -8, 0, 3, 8, 0, 7, -3, 5, 7, 3, 5, 3, 8, 0, -3, -8, 0, 3, -8, 0, 3, 8, 0, -3, -8, 0, -3, 8, 0, -3, 8, 0, -7, -3, 5, -3, -8, 0, -3, 8, 0, -7, -3, 5, -7, 3, 5];
    const _0x1ebfe3 = this.create_vbo(_0x2626af);
    this.gl.bindBuffer(this.gl.ARRAY_BUFFER, _0x1ebfe3);
    this.gl.enableVertexAttribArray(_0x18111e[0]);
    this.gl.vertexAttribPointer(_0x18111e[0], _0x15ddf2[0], this.gl.FLOAT, false, 0, 0);
    const _0x570653 = new matIV();
    const _0x5a4b24 = _0x570653.identity(_0x570653.create());
    const _0x5f594b = _0x570653.identity(_0x570653.create());
    const _0x15df66 = _0x570653.identity(_0x570653.create());
    const _0x28d80f = _0x570653.identity(_0x570653.create());
    const _0xf54bc7 = (_0x39f658 - this.timeLoad) / 1e3;
    const _0x404188 = [Math.sin(Math.sin(_0xf54bc7) / 3), Math.cos(Math.sin(_0xf54bc7) / 3), 0];
    _0x570653.lookAt([0, 0, 5], [0, 0, 0], _0x404188, _0x5f594b);
    _0x570653.perspective(90, this.canvas.width / this.canvas.height, 0.1, 100, _0x15df66);
    _0x570653.multiply(_0x15df66, _0x5f594b, _0x28d80f);
    _0x570653.multiply(_0x28d80f, _0x5a4b24, _0x28d80f);
    const _0x4d0a27 = this.gl.getUniformLocation(this.prg, "mvpMatrix");
    this.gl.uniformMatrix4fv(_0x4d0a27, false, _0x28d80f);
    const _0x504e76 = this.gl.getUniformLocation(this.prg, "u_time");
    this.gl.uniform1f(_0x504e76, _0xf54bc7);
    const _0x15e050 = this.gl.getUniformLocation(this.prg, "u_resolution");
    this.gl.uniform2f(_0x15e050, this.canvas.width, this.canvas.height);
    this.gl.useProgram(this.prg);
    this.gl.drawArrays(this.gl.TRIANGLES, 0, 18);
    this.gl.flush();
  }
  ["create_shader"](_0x217f95, _0x50b1bf) {
    let _0x333f8e;
    switch (_0x50b1bf) {
      case "OuO":
        _0x333f8e = this.gl.createShader(this.gl.VERTEX_SHADER);
        break;
      case ">w<":
        _0x333f8e = this.gl.createShader(this.gl.FRAGMENT_SHADER);
        break;
      default:
        return;
    }
    this.gl.shaderSource(_0x333f8e, _0x217f95);
    this.gl.compileShader(_0x333f8e);
    if (this.gl.getShaderParameter(_0x333f8e, this.gl.COMPILE_STATUS)) {
      return _0x333f8e;
    } else {
      alert(this.gl.getShaderInfoLog(_0x333f8e));
    }
  }
  ["create_program"](_0x4d159e, _0x135a44) {
    const _0x171a80 = this.gl.createProgram();
    this.gl.attachShader(_0x171a80, _0x4d159e);
    this.gl.attachShader(_0x171a80, _0x135a44);
    this.gl.linkProgram(_0x171a80);
    if (this.gl.getProgramParameter(_0x171a80, this.gl.LINK_STATUS)) {
      this.gl.useProgram(_0x171a80);
      return _0x171a80;
    } else {
      alert(this.gl.getProgramInfoLog(_0x171a80));
    }
  }
  ["create_vbo"](_0xbcae1c) {
    const _0x9500e2 = this.gl.createBuffer();
    this.gl.bindBuffer(this.gl.ARRAY_BUFFER, _0x9500e2);
    this.gl.bufferData(this.gl.ARRAY_BUFFER, new Float32Array(_0xbcae1c), this.gl.STATIC_DRAW);
    this.gl.bindBuffer(this.gl.ARRAY_BUFFER, null);
    return _0x9500e2;
  }
}

canvasCalcObj = new _0x36ee9a_("canvas-calc", 650, 650, "\n  attribute vec3 position;\n  varying   float owO;\n  \n  void main(void){\n      gl_Position = vec4(position.xy, 0.0, 1.0);\n      owO = position.z;\n  }\n  ", "\n#ifdef GL_ES\nprecision highp float;\n#endif            \nvarying float owO;\n#define OvO 255.0\n#define Ovo 128.0\n#define OVO 23.0\n\nfloat OwO (float Owo, float OWO, float owO) { \n    OWO = floor(OWO + 0.5); owO = floor(owO + 0.5); \n    return mod(floor((floor(Owo) + 0.5) / exp2(OWO)), floor(1.0*exp2(owO - OWO) + 0.5)); \n}\nvec4 oWo (float Ow0) { \n    if (Ow0 == 0.0) return vec4(0.0); \n    float Owo = Ow0 > 0.0 ? 0.0 : 1.0; \n    Ow0 = abs(Ow0); \n    float OWO = floor(log2(Ow0)); \n    float oWo = OWO + OvO - Ovo; \n    OWO = ((Ow0 / exp2(OWO)) - 1.0) * pow(2.0, OVO);\n    float owO = oWo / 2.0; \n    oWo = fract(owO) + fract(owO); \n    float oWO = floor(owO); \n    owO = OwO(OWO, 0.0, 8.0) / OvO; \n    Ow0 = OwO(OWO, 8.0, 16.0) / OvO; \n    OWO = (oWo * Ovo + OwO(OWO, 16.0, OVO)) / OvO; \n    Owo = (Owo * Ovo + oWO) / OvO; \n    return vec4(owO, Ow0, OWO, Owo); \n}\n\nvoid main()\n{\n    gl_FragColor = oWo(owO);\n}\n  ", false);
canvasCalcObj.render();


/* Recall equations from `computeFlag`:

function computeFlag(p1) {
  // p1 is an array of star UIDs
  let i_19_03_05 = canvasCalcObj.wtf(p1[19], p1[3],  p1[5])  * 25;
  let i_07_20_18 = canvasCalcObj.wtf(p1[7],  p1[20], p1[18]) * 25;
  let i_11_22_18 = canvasCalcObj.wtf(p1[11], p1[22], p1[18]) * 25;
  let i_05_17_02 = canvasCalcObj.wtf(p1[5],  p1[17], p1[2])  * 25;
  let i_20_13_05 = canvasCalcObj.wtf(p1[20], p1[13], p1[5])  * 25;
  let i_11_01_21 = canvasCalcObj.wtf(p1[11], p1[1],  p1[21]) * 25;
  let i_08_11_01 = canvasCalcObj.wtf(p1[8],  p1[11], p1[1])  * 25;
  let i_09_05_04 = canvasCalcObj.wtf(p1[9],  p1[5],  p1[4])  * 25;
  let i_17_09_21 = canvasCalcObj.wtf(p1[17], p1[9],  p1[21]) * 25;
  let i_23_09_20 = canvasCalcObj.wtf(p1[23], p1[9],  p1[20]) * 25;
  let i_16_05_04 = canvasCalcObj.wtf(p1[16], p1[5],  p1[4])  * 25;
  let i_16_14_13 = canvasCalcObj.wtf(p1[16], p1[14], p1[13]) * 25;
  let i_05_06_10 = canvasCalcObj.wtf(p1[5],  p1[6],  p1[10]) * 25;
  let i_02_11_05 = canvasCalcObj.wtf(p1[2],  p1[11], p1[5])  * 25;
  let i_11_03_01 = canvasCalcObj.wtf(p1[11], p1[3],  p1[1])  * 25;
  let i_12_03_10 = canvasCalcObj.wtf(p1[12], p1[3],  p1[10]) * 25;
  let i_14_01_09 = canvasCalcObj.wtf(p1[14], p1[1],  p1[9])  * 25;
  let i_18_11_17 = canvasCalcObj.wtf(p1[18], p1[11], p1[17]) * 25;
  let i_12_15_02 = canvasCalcObj.wtf(p1[12], p1[15], p1[2])  * 25;
  let i_22_00_19 = canvasCalcObj.wtf(p1[22], p1[0],  p1[19]) * 25;

  let _0x5c13fb = 0;
  // All these should be 0
  _0x5c13fb += Math.abs(0.3837876686390533  - canvasCalcObj.gtfo(i_11_01_21, i_14_01_09, i_17_09_21, 16, 21));
  _0x5c13fb += Math.abs(0.21054889940828397 - canvasCalcObj.gtfo(i_11_03_01, i_11_01_21, i_08_11_01, 8, 2));
  _0x5c13fb += Math.abs(0.475323349112426   - canvasCalcObj.gtfo(i_11_01_21, i_18_11_17, i_05_06_10, 0, 20));
  _0x5c13fb += Math.abs(0.6338370887573964  - canvasCalcObj.gtfo(i_05_17_02, i_07_20_18, i_05_06_10, 8, 4));
  _0x5c13fb += Math.abs(0.4111607928994082  - canvasCalcObj.gtfo(i_11_22_18, i_11_03_01, i_12_03_10, 23, 1));
  _0x5c13fb += Math.abs(0.7707577751479291  - canvasCalcObj.gtfo(i_18_11_17, i_05_17_02, i_16_14_13, 20, 6));
  _0x5c13fb += Math.abs(0.7743081420118344  - canvasCalcObj.gtfo(i_23_09_20, i_02_11_05, i_05_17_02, 9, 10));
  _0x5c13fb += Math.abs(0.36471487573964495 - canvasCalcObj.gtfo(i_17_09_21, i_19_03_05, i_20_13_05, 18, 8));
  _0x5c13fb += Math.abs(0.312678449704142   - canvasCalcObj.gtfo(i_12_03_10, i_23_09_20, i_18_11_17, 0, 17));
  _0x5c13fb += Math.abs(0.9502808165680473  - canvasCalcObj.gtfo(i_12_15_02, i_23_09_20, i_05_17_02, 22, 10));
  _0x5c13fb += Math.abs(0.5869052899408282  - canvasCalcObj.gtfo(i_05_06_10, i_09_05_04, i_11_22_18, 14, 10));
  _0x5c13fb += Math.abs(0.9323389467455623  - canvasCalcObj.gtfo(i_18_11_17, i_11_22_18, i_05_06_10, 12, 7));
  _0x5c13fb += Math.abs(0.4587118106508875  - canvasCalcObj.gtfo(i_08_11_01, i_02_11_05, i_11_22_18, 4, 21));
  _0x5c13fb += Math.abs(0.14484472189349107 - canvasCalcObj.gtfo(i_12_03_10, i_23_09_20, i_11_03_01, 7, 15));
  _0x5c13fb += Math.abs(0.7255550059171598  - canvasCalcObj.gtfo(i_11_01_21, i_18_11_17, i_12_15_02, 9, 23));
  _0x5c13fb += Math.abs(0.5031261301775147  - canvasCalcObj.gtfo(i_05_17_02, i_11_22_18, i_11_03_01, 7, 1));
  _0x5c13fb += Math.abs(0.1417352189349112  - canvasCalcObj.gtfo(i_08_11_01, i_11_03_01, i_17_09_21, 16, 14));
  _0x5c13fb += Math.abs(0.5579334437869822  - canvasCalcObj.gtfo(i_11_03_01, i_11_22_18, i_12_15_02, 19, 11));
  _0x5c13fb += Math.abs(0.48502262721893485 - canvasCalcObj.gtfo(i_16_05_04, i_20_13_05, i_09_05_04, 23, 18));
  _0x5c13fb += Math.abs(0.5920916568047336  - canvasCalcObj.gtfo(i_09_05_04, i_17_09_21, i_07_20_18, 19, 6));
  _0x5c13fb += Math.abs(0.7222713017751479  - canvasCalcObj.gtfo(i_14_01_09, i_11_22_18, i_20_13_05, 8, 16));
  _0x5c13fb += Math.abs(0.12367382248520711 - canvasCalcObj.gtfo(i_16_05_04, i_12_03_10, i_05_06_10, 9, 5));
  _0x5c13fb += Math.abs(0.4558028402366864  - canvasCalcObj.gtfo(i_16_14_13, i_16_05_04, i_11_22_18, 10, 2));
  _0x5c13fb += Math.abs(0.8537692426035504  - canvasCalcObj.gtfo(i_18_11_17, i_23_09_20, i_02_11_05, 4, 11));
  _0x5c13fb += Math.abs(0.9618170650887574  - canvasCalcObj.gtfo(i_05_06_10, i_12_15_02, i_18_11_17, 15, 2));
  _0x5c13fb += Math.abs(0.22088933727810647 - canvasCalcObj.gtfo(i_19_03_05, i_09_05_04, i_14_01_09, 10, 5));
  _0x5c13fb += Math.abs(0.4302783550295858  - canvasCalcObj.gtfo(i_14_01_09, i_16_14_13, i_11_01_21, 14, 2));
  _0x5c13fb += Math.abs(0.6262803313609467  - canvasCalcObj.gtfo(i_22_00_19, i_11_03_01, i_11_22_18, 17, 22));

  if (_0x5c13fb > 0.00001) {
    return null;
  }

  // ..... 

  return _0x16a9e1;
}
*/

/* Precompute all possible results (25*25*25 = 15625) of wtf(). */
function build_wtf_cache() {
  let wtf_cache = {};

  for (let i=0; i<25; i++) {
    for (let j=0; j<25; j++) {
      for (let k=0; k<25; k++) {
        let v = canvasCalcObj.wtf(i, j, k) * 25
        wtf_cache[`${i},${j},${k}`] = v
      } 
    }
  }

  return wtf_cache;
}

/* Brute force a `gtfo` with 5 unknown points. */
function bruteforce_5(init_p1, eval_callback) {
  let solutions = 'var arr = [\n'
  p1 = init_p1;

  for (let i=0; i<25; ++i) {
    console.log(`i: ${i}`)
    for (let j=1; j<25; ++j) {
      console.log(`    j: ${j}`)
      // We have a permutation, so all numbers must be different.
      if (j == i) continue;
    
      for (let k=0; k<25; ++k) {
        if (k == i || k == j) continue;  
        for (let l=0; l<25; ++l) {
          if (l == i || l == j || l == k) continue;    
          for (let m=0; m<25; ++m) {
            if (m == i || m == j || m == k || m == l) continue;

            const [is_sol, res] = eval_callback(i, j, k, l, m)
            if (is_sol) {
              console.log(`Solution FOUND: ${i}, ${j}, ${k}, ${l}, ${m} ~> ${res}`)
              solutions += `    [${i}, ${j}, ${k}, ${l}, ${m}, ${res}],\n`;
            }
          }
        }
      }
    }
  }

  solutions += '];'
  return solutions;
}

/* Brute force a `gtfo` with 4 unknown points. */
function bruteforce_4(init_p1, prev_res, eval_callback) {
  let solutions = ''
  p1 = init_p1;

  for (let i=0; i<25; ++i) {
    console.log(`i: ${i}`)
    for (let j=1; j<25; ++j) {
      if (j == i) continue;  
      for (let k=0; k<25; ++k) {
        if (k == i || k == j) continue;  
        for (let l=0; l<25; ++l) {
          if (l == i || l == j || l == k) continue;    

          const [is_sol, res] = eval_callback(i, j, k, l, prev_res)
          if (is_sol) {
            console.log(`Solution FOUND: ${i}, ${j}, ${k}, ${l} ~> ${res}`)
            solutions += `    [${p1}, ${res}],\n`;
          }
        }
      }
    }
  }

  return solutions;
}

/* Brute force a `gtfo` with 3 unknown points. */
function bruteforce_3(init_p1, prev_res, eval_callback) {
  let solutions = ''
  p1 = init_p1;

  for (let i=0; i<25; ++i) {
    for (let j=1; j<25; ++j) {
      if (j == i) continue;  
      for (let k=0; k<25; ++k) {
        if (k == i || k == j) continue;  

        const [is_sol, res] = eval_callback(i, j, k, prev_res)
        if (is_sol) {
          console.log(`Solution FOUND: ${i}, ${j}, ${k} ~> ${res}`)
          solutions += `    [${p1}, ${res}],\n`;
        }
      }
    }
  }

  return solutions;
}

/* Brute force a `gtfo` with 2 unknown points. */
function bruteforce_2(init_p1, prev_res, eval_callback) {
  let solutions = ''
  p1 = init_p1;

  for (let i=0; i<25; ++i) {
    for (let j=1; j<25; ++j) {
      if (j == i) continue;
      const [is_sol, res] = eval_callback(i, j, prev_res)
      if (is_sol) {
        console.log(`Solution FOUND: ${i}, ${j} ~> ${res}`)
        solutions += `    [${p1}, ${res}],\n`;
      }
    }
  }

  return solutions;
}

/* Brute force a `gtfo` with 1 unknown point. */
function bruteforce_1(init_p1, prev_res, eval_callback) {
  let solutions = ''
  p1 = init_p1;

  for (let i=0; i<25; ++i) {
      const [is_sol, res] = eval_callback(i, prev_res)
      if (is_sol) {
        console.log(`Solution FOUND: ${i} ~> ${res}`)
        solutions += `    [${p1}, ${res}],\n`;
      }
  }
  
  return solutions;
}

/* Checks if all numbers (except -1s) in p1 are different. */
function are_all_different(p1) {
  let visited = new Set();
  
  for (let i=0; i<p1.length; ++i) {
    if (p1[i] == -1) continue; // Ignore -1.

    if (visited.has(p1[i])) {
      return false;  // Found a duplicate.
    }

    visited.add(p1[i])
  }

  return true; // All are unique.
}


var cache = build_wtf_cache();
console.log('wtf cache ok');

p1 = [-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1];

// BRUTE FORCE:
// Math.abs(0.21054889940828397 - canvasCalcObj.gtfo(i_11_03_01, i_11_01_21, i_08_11_01, 8,  2 )); ~> {1, 3, 21, 8, 11}
/*
solutions = bruteforce_5(
  p1,
  function(i, j, k, l, m) {
    p1[1]  = i;
    p1[3]  = j;
    p1[8]  = k;
    p1[11] = l;
    p1[21] = m;

    let i_11_03_01 = cache[`${p1[11]},${p1[3]},${p1[1]}`];
    let i_11_01_21 = cache[`${p1[11]},${p1[1]},${p1[21]}`];
    let i_08_11_01 = cache[`${p1[8]},${p1[11]},${p1[1]}`];          

    let res = canvasCalcObj.gtfo(i_11_03_01, i_11_01_21, i_08_11_01, 8, 2);
    return [Math.abs(0.21054889940828397 - res) < 0.00001, res];
  })

console.log(solutions)
*/

// The above code runs in ~4hrs. Use the results directly.
var arr = [
    [0, 2, 12, 18, 1, 0.210551321506500],
    [1, 18, 0, 15, 17, 0.210552215576172],
    [1, 18, 23, 6, 8, 0.210557579994202],
    [1, 20, 11, 23, 0, 0.210556268692017],
    [2, 24, 4, 23, 5, 0.210543364286423],
    [3, 4, 15, 0, 7, 0.210557863116264],
    [3, 6, 20, 23, 15, 0.210545688867569],
    [4, 8, 13, 12, 9, 0.210557505488396],
    [5, 6, 2, 15, 7, 0.210553169250488],
    [5, 6, 21, 3, 15, 0.210541903972626],
    [5, 8, 2, 15, 7, 0.210545197129250],
    [5, 14, 21, 3, 15, 0.210557863116264],
    [5, 16, 21, 3, 15, 0.210549890995026],
    [6, 14, 1, 10, 20, 0.210540086030960],
    [6, 14, 10, 17, 11, 0.210540726780891],
    [6, 20, 1, 12, 21, 0.210549518465996],
    [6, 23, 3, 24, 4, 0.210544779896736],
    [7, 17, 1, 15, 22, 0.210543572902679],
    [7, 17, 21, 5, 8, 0.210557833313942],
    [7, 22, 19, 2, 21, 0.210548713803291],
    [8, 0, 22, 10, 9, 0.210546076297760],
    [8, 15, 3, 5, 6, 0.210558801889420],
    [8, 23, 7, 24, 2, 0.210544928908348],
    [9, 3, 20, 23, 5, 0.210547670722008],
    [9, 5, 11, 13, 7, 0.210546553134918],
    [9, 15, 19, 23, 18, 0.210541203618050],
    [9, 15, 23, 6, 1, 0.210548877716064],
    [9, 21, 18, 24, 2, 0.210557371377945],
    [9, 21, 22, 16, 20, 0.210544168949127],
    [10, 4, 7, 8, 21, 0.210557714104652],
    [10, 22, 11, 0, 12, 0.210542678833008],
    [11, 5, 12, 9, 20, 0.210554435849190],
    [11, 12, 2, 20, 5, 0.210557460784912],
    [11, 12, 24, 17, 5, 0.210553288459778],
    [11, 13, 10, 0, 18, 0.210557699203491],
    [11, 13, 17, 9, 24, 0.210553795099258],
    [11, 17, 13, 5, 20, 0.210547134280205],
    [11, 19, 1, 15, 21, 0.210549846291542],
    [13, 8, 1, 15, 24, 0.210540935397148],
    [13, 17, 14, 2, 18, 0.210553467273712],
    [14, 8, 12, 0, 24, 0.210540175437927],
    [14, 13, 7, 20, 3, 0.210543692111969],
    [14, 18, 13, 21, 16, 0.210545331239700],
    [14, 20, 11, 10, 6, 0.210541576147079],
    [14, 23, 9, 7, 1, 0.210552453994751],
    [15, 11, 0, 2, 14, 0.210551097989082],
    [15, 19, 14, 2, 4, 0.210543155670166],
    [15, 20, 12, 9, 14, 0.210546970367432],
    [16, 8, 12, 2, 13, 0.210551097989082],
    [16, 15, 5, 9, 12, 0.210545331239700],
    [16, 15, 14, 22, 19, 0.210547164082527],
    [16, 23, 22, 12, 14, 0.210547924041748],
    [17, 0, 22, 14, 1, 0.210554212331772],
    [17, 2, 8, 4, 7, 0.210555911064148],
    [17, 5, 4, 19, 14, 0.210552170872688],
    [18, 12, 2, 23, 22, 0.210551321506500],
    [18, 14, 2, 15, 6, 0.210552141070366],
    [18, 21, 20, 23, 24, 0.210552498698235],
    [19, 4, 5, 8, 9, 0.210554674267769],
    [19, 12, 3, 20, 17, 0.210543945431709],
    [20, 5, 14, 23, 13, 0.210552603006363],
    [20, 6, 17, 23, 15, 0.210555493831635],
    [20, 18, 15, 2, 12, 0.210541978478432],
    [20, 21, 7, 16, 12, 0.210540339350700],
    [21, 0, 5, 12, 16, 0.210555389523506],
    [22, 6, 0, 18, 1, 0.210553362965584],
    [22, 12, 20, 21, 4, 0.210553422570229],
    [23, 10, 13, 6, 16, 0.210549712181091],
    [23, 12, 13, 2, 20, 0.210544377565384],
    [23, 18, 0, 10, 9, 0.210554808378220],
    [23, 19, 24, 20, 8, 0.210550010204315],
    [23, 22, 20, 10, 5, 0.210541084408760],
    [24, 13, 7, 8, 4, 0.210541307926178],
];

// BRUTE FORCE:
// Math.abs(0.3837876686390533  - canvasCalcObj.gtfo(i_11_01_21, i_14_01_09, i_17_09_21, 16, 21));
solutions = 'var arr2 = [\n'
for (let i=0; i<arr.length; ++i) {
  console.log(`Trying solution: ${arr[i]}`)

  p1[1]  = arr[i][0];  // Use solution from previous bruteforce.
  p1[3]  = arr[i][1];
  p1[8]  = arr[i][2];
  p1[11] = arr[i][3];
  p1[21] = arr[i][4];

  solutions += bruteforce_3(
    p1,
    arr[i][5],
    function(i, j, k, trg) {
      p1[9]  = i;
      p1[14] = j;
      p1[17] = k;

      if (!are_all_different(p1)) {
        return [false, 0];
      }

      let i_11_01_21 = cache[`${p1[11]},${p1[1]},${p1[21]}`];
      let i_14_01_09 = cache[`${p1[14]},${p1[1]},${p1[9]}`];
      let i_17_09_21 = cache[`${p1[17]},${p1[9]},${p1[21]}`];        

      let res = canvasCalcObj.gtfo(i_11_01_21, i_14_01_09, i_17_09_21, 16, 21);
      trg  = Math.abs(0.3837876686390533 - res);
      trg += Math.abs(0.21054889940828397 - trg); // Add previous result to limit solutions.

      return [trg < 0.00001, res];
    })  
}
solutions += '];';
console.log(solutions);


var arr2 = [
    [-1,6,-1,23,-1,-1,-1,-1,3,14,-1,24,-1,-1,21,-1,-1,5,-1,-1,,4, 0.383789032697678],
    [-1,7,-1,17,-1,-1,-1,-1,21,1,-1,5,-1,-1,2,-1,-1,16,-1,-1,,8, 0.383789300918579],
    [-1,9,-1,15,-1,-1,-1,-1,23,5,-1,6,-1,-1,12,-1,-1,13,-1,-1,,1, 0.383787631988525],
    [-1,11,-1,5,-1,-1,-1,-1,12,8,-1,9,-1,-1,1,-1,-1,18,-1,-1,,20, 0.383787006139755],
    [-1,14,-1,18,-1,-1,-1,-1,13,23,-1,21,-1,-1,9,-1,-1,6,-1,-1,,16, 0.383787542581558],
    [-1,14,-1,23,-1,-1,-1,-1,9,6,-1,7,-1,-1,11,-1,-1,4,-1,-1,,1, 0.383794128894806],
    [-1,14,-1,23,-1,-1,-1,-1,9,10,-1,7,-1,-1,5,-1,-1,21,-1,-1,,1, 0.383787423372269],
    [-1,17,-1,5,-1,-1,-1,-1,4,6,-1,19,-1,-1,2,-1,-1,8,-1,-1,,14, 0.383788257837296],
    [-1,18,-1,14,-1,-1,-1,-1,2,12,-1,15,-1,-1,11,-1,-1,10,-1,-1,,6, 0.383790820837021],
];

// BRUTE FORCE:
// Math.abs(0.475323349112426   - canvasCalcObj.gtfo(i_11_01_21, i_18_11_17, i_05_06_10, 0,  20)); ~> {10, 18, 5, 6}
solutions = 'arr3 = [\n'
for (let i=0; i<arr2.length; ++i) {
  console.log(`Trying solution: ${arr2[i]}`)

  p1[1]  = arr2[i][1];  // Use solution from previous bruteforce.
  p1[3]  = arr2[i][3];
  p1[8]  = arr2[i][8];
  p1[11] = arr2[i][11];
  p1[21] = arr2[i][21];

  p1[9]  = arr2[i][9];
  p1[14] = arr2[i][14];
  p1[17] = arr2[i][17];

  solutions += bruteforce_4(
    p1,
    arr2[i][22],
    function(i, j, k, l, prev_res) {
      p1[5]  = i;
      p1[6]  = j;
      p1[10] = k;
      p1[18] = l;
      
      if (!are_all_different(p1)) {
        return [false, 0];
      }

      let i_11_01_21 = cache[`${p1[11]},${p1[1]},${p1[21]}`];
      let i_18_11_17 = cache[`${p1[18]},${p1[11]},${p1[17]}`];
      let i_05_06_10 = cache[`${p1[5]},${p1[6]},${p1[10]}`];          
      var res = canvasCalcObj.gtfo(i_11_01_21, i_18_11_17, i_05_06_10, 0, 20);

      trg  = Math.abs(0.475323349112426 - res);
      trg += Math.abs(0.3837876686390533 - prev_res); // Add previous result to limit solutions.

      return [trg < 0.00001, res];
    })  
}
solutions += '];';
console.log(solutions);


var arr3 = [
    [-1,9,-1,15,-1,0,22,-1,23,5,17,6,-1,-1,12,-1,-1,13,4,-1,,1, 0.475328475236893],
    [-1,9,-1,15,-1,4,11,-1,23,5,8,6,-1,-1,12,-1,-1,13,0,-1,,1, 0.475326836109161],
    [-1,9,-1,15,-1,4,20,-1,23,5,14,6,-1,-1,12,-1,-1,13,18,-1,,1, 0.475316017866135],
    [-1,9,-1,15,-1,4,21,-1,23,5,16,6,-1,-1,12,-1,-1,13,0,-1,,1, 0.475322544574738],
    [-1,9,-1,15,-1,18,17,-1,23,5,0,6,-1,-1,12,-1,-1,13,16,-1,,1, 0.475323319435120],
    [-1,9,-1,15,-1,20,17,-1,23,5,2,6,-1,-1,12,-1,-1,13,14,-1,,1, 0.475332111120224],
    [-1,9,-1,15,-1,21,17,-1,23,5,11,6,-1,-1,12,-1,-1,13,8,-1,,1, 0.475326478481293],
    [-1,9,-1,15,-1,24,7,-1,23,5,2,6,-1,-1,12,-1,-1,13,21,-1,,1, 0.475315958261490],
];

// BRUTE FORCE:
// Math.abs(0.5579334437869822  - canvasCalcObj.gtfo(i_11_03_01, i_11_22_18, i_12_15_02, 19, 11)); ~> {2, 12, 22, 15}
solutions = 'arr4 = [\n'
for (let i=0; i<arr3.length; ++i) {
  console.log(`Trying solution: ${arr3[i]}`)

  p1[1]  = arr3[i][1];  // Use solution from previous bruteforce.
  p1[3]  = arr3[i][3];
  p1[8]  = arr3[i][8];
  p1[11] = arr3[i][11];
  p1[21] = arr3[i][21];

  p1[9]  = arr3[i][9];
  p1[14] = arr3[i][14];
  p1[17] = arr3[i][17];
  
  p1[5]  = arr3[i][5];
  p1[6]  = arr3[i][6];
  p1[10] = arr3[i][10];
  p1[18] = arr3[i][18];

  solutions += bruteforce_4(
    p1,
    arr3[i][22],
    function(i, j, k, l, prev_res) {
      p1[2]  = i;
      p1[12] = j;
      p1[15] = k;
      p1[22] = l;
      
      if (!are_all_different(p1)) {
        return [false, 0];
      }

      let i_11_03_01 = cache[`${p1[11]},${p1[3]},${p1[1]}`];
      let i_11_22_18 = cache[`${p1[11]},${p1[22]},${p1[18]}`];
      let i_12_15_02 = cache[`${p1[12]},${p1[15]},${p1[2]}`];          
      var res = canvasCalcObj.gtfo(i_11_03_01, i_11_22_18, i_12_15_02, 19, 11)

      trg  = Math.abs(0.5579334437869822 - res);
      trg += Math.abs(0.475323349112426 - prev_res); // Add previous result to limit solutions.

      return [trg < 0.00001, res];
    })  
}
solutions += '];';
console.log(solutions);


var arr4 = [
    [-1,9,8,15,-1,18,17,-1,23,5,0,6,24,-1,12,11,-1,13,16,-1,,1,21, 0.557933449745178],
];  

// BRUTE FORCE:
// Math.abs(0.48502262721893485 - canvasCalcObj.gtfo(i_16_05_04, i_20_13_05, i_09_05_04, 23, 18)); ~> {16, 20, 4, 13}
solutions = 'arr5 = [\n'
for (let i=0; i<arr4.length; ++i) {
  console.log(`Trying solution: ${arr4[i]}`)

  p1[1]  = arr4[i][1];  // Use solution from previous bruteforce.
  p1[3]  = arr4[i][3];
  p1[8]  = arr4[i][8];
  p1[11] = arr4[i][11];
  p1[21] = arr4[i][21];

  p1[9]  = arr4[i][9];
  p1[14] = arr4[i][14];
  p1[17] = arr4[i][17];
  
  p1[5]  = arr4[i][5];
  p1[6]  = arr4[i][6];
  p1[10] = arr4[i][10];
  p1[18] = arr4[i][18];

  p1[2]  = arr4[i][2];
  p1[12] = arr4[i][12];
  p1[15] = arr4[i][15];
  p1[22] = arr4[i][22];  

  solutions += bruteforce_4(
    p1,
    arr4[i][23], // It's not 23, not 22.
    function(i, j, k, l, prev_res) {
      p1[4]  = i;
      p1[13] = j;
      p1[16] = k;
      p1[20] = l;
      
      if (!are_all_different(p1)) {
        return [false, 0];
      }

      let i_16_05_04 = cache[`${p1[16]},${p1[5]},${p1[4]}`];
      let i_20_13_05 = cache[`${p1[20]},${p1[13]},${p1[5]}`];
      let i_09_05_04 = cache[`${p1[9]},${p1[5]},${p1[4]}`];          
      var res = canvasCalcObj.gtfo(i_16_05_04, i_20_13_05, i_09_05_04, 23, 18)

      trg  = Math.abs(0.48502262721893485 - res);
      trg += Math.abs(0.5579334437869822 - prev_res); // Add previous result to limit solutions.

      return [trg < 0.00001, res];
    })  
}
solutions += '];';
console.log(solutions);

var arr5 = [
  [-1,9,8,15,3,18,17,-1,23,5,0,6,24,14,12,11,2,13,16,-1,7,1,21, 0.485022634267807],
];  

// BRUTE FORCE:
// Math.abs(0.6262803313609467  - canvasCalcObj.gtfo(i_22_00_19, i_11_03_01, i_11_22_18, 17, 22)); ~> {0, 19}
solutions = 'arr6 = [\n'
for (let i=0; i<arr5.length; ++i) {
  console.log(`Trying solution: ${arr5[i]}`)

  p1[1]  = arr5[i][1];  // Use solution from previous bruteforce.
  p1[3]  = arr5[i][3];
  p1[8]  = arr5[i][8];
  p1[11] = arr5[i][11];
  p1[21] = arr5[i][21];

  p1[9]  = arr5[i][9];
  p1[14] = arr5[i][14];
  p1[17] = arr5[i][17];
  
  p1[5]  = arr5[i][5];
  p1[6]  = arr5[i][6];
  p1[10] = arr5[i][10];
  p1[18] = arr5[i][18];

  p1[2]  = arr5[i][2];
  p1[12] = arr5[i][12];
  p1[15] = arr5[i][15];
  p1[22] = arr5[i][22];  

  p1[4]  = arr5[i][4];
  p1[13] = arr5[i][13];
  p1[16] = arr5[i][16];
  p1[20] = arr5[i][20];
  
  solutions += bruteforce_2(
    p1,
    arr5[i][23], // It's not 23, not 22.
    function(i, j, prev_res) {
      p1[0]  = i;
      p1[19] = j;
      
      if (!are_all_different(p1)) {
        return [false, 0];
      }

      let i_22_00_19 = cache[`${p1[22]},${p1[0]},${p1[19]}`];
      let i_11_03_01 = cache[`${p1[11]},${p1[3]},${p1[1]}`];
      let i_11_22_18 = cache[`${p1[11]},${p1[22]},${p1[18]}`];          
      var res = canvasCalcObj.gtfo(i_22_00_19, i_11_03_01, i_11_22_18, 17, 22)

      trg  = Math.abs(0.6262803313609467 - res);
      trg += Math.abs(0.48502262721893485 - prev_res); // Add previous result to limit solutions.

      return [trg < 0.00001, res];
    })  
}
solutions += '];';
console.log(solutions);

arr6 = [
    [19,9,8,15,3,18,17,-1,23,5,0,6,24,14,12,11,2,13,16,4,7,1,21, 0.626280307769775],
];

// BRUTE FORCE:
// Math.abs(0.6338370887573964  - canvasCalcObj.gtfo(i_05_17_02, i_07_20_18, i_05_06_10, 8,  4 )); ~> {7}
solutions = 'arr7 = [\n'
for (let i=0; i<arr6.length; ++i) {
  console.log(`Trying solution: ${arr6[i]}`)

  p1[1]  = arr6[i][1];  // Use solution from previous bruteforce.
  p1[3]  = arr6[i][3];
  p1[8]  = arr6[i][8];
  p1[11] = arr6[i][11];
  p1[21] = arr6[i][21];

  p1[9]  = arr6[i][9];
  p1[14] = arr6[i][14];
  p1[17] = arr6[i][17];
  
  p1[5]  = arr6[i][5];
  p1[6]  = arr6[i][6];
  p1[10] = arr6[i][10];
  p1[18] = arr6[i][18];

  p1[2]  = arr6[i][2];
  p1[12] = arr6[i][12];
  p1[15] = arr6[i][15];
  p1[22] = arr6[i][22];  

  p1[4]  = arr6[i][4];
  p1[13] = arr6[i][13];
  p1[16] = arr6[i][16];
  p1[20] = arr6[i][20];
  
  p1[0]  = arr6[i][0];
  p1[19] = arr6[i][19];

  solutions += bruteforce_1(
    p1,
    arr6[i][23], // It's not 23, not 22.
    function(i, prev_res) {
      p1[7] = i;
      
      if (!are_all_different(p1)) {
        return [false, 0];
      }

      let i_05_17_02 = cache[`${p1[5]},${p1[17]},${p1[2]}`];
      let i_07_20_18 = cache[`${p1[7]},${p1[20]},${p1[18]}`];
      let i_05_06_10 = cache[`${p1[5]},${p1[6]},${p1[10]}`];          
      var res = canvasCalcObj.gtfo(i_05_17_02, i_07_20_18, i_05_06_10, 8, 4)

      trg  = Math.abs(0.6338370887573964 - res);
      trg += Math.abs(0.6262803313609467 - prev_res); // Add previous result to limit solutions.

      return [trg < 0.00001, res];
    })  
}
solutions += '];';
console.log(solutions);

arr7 = [
    [19,9,8,15,3,18,17,10,23,5,0,6,24,14,12,11,2,13,16,4,7,1,21, 0.633837103843689],
];

// BRUTE FORCE:
// Math.abs(0.7743081420118344  - canvasCalcObj.gtfo(i_23_09_20, i_02_11_05, i_05_17_02, 9,  10)); ~> {23}
solutions = 'arr8 = [\n'
for (let i=0; i<arr7.length; ++i) {
  console.log(`Trying solution: ${arr7[i]}`)

  p1[1]  = arr7[i][1];  // Use solution from previous bruteforce.
  p1[3]  = arr7[i][3];
  p1[8]  = arr7[i][8];
  p1[11] = arr7[i][11];
  p1[21] = arr7[i][21];

  p1[9]  = arr7[i][9];
  p1[14] = arr7[i][14];
  p1[17] = arr7[i][17];
  
  p1[5]  = arr7[i][5];
  p1[6]  = arr7[i][6];
  p1[10] = arr7[i][10];
  p1[18] = arr7[i][18];

  p1[2]  = arr7[i][2];
  p1[12] = arr7[i][12];
  p1[15] = arr7[i][15];
  p1[22] = arr7[i][22];  

  p1[4]  = arr7[i][4];
  p1[13] = arr7[i][13];
  p1[16] = arr7[i][16];
  p1[20] = arr7[i][20];
  
  p1[0]  = arr7[i][0];
  p1[19] = arr7[i][19];

  p1[7] = arr7[i][7];

  solutions += bruteforce_1(
    p1,
    arr7[i][23], // It's not 23, not 22.
    function(i, prev_res) {
      p1[23] = i;
      
      if (!are_all_different(p1)) {
        return [false, 0];
      }

      let i_23_09_20 = cache[`${p1[23]},${p1[9]},${p1[20]}`];
      let i_02_11_05 = cache[`${p1[2]},${p1[11]},${p1[5]}`];
      let i_05_17_02 = cache[`${p1[5]},${p1[17]},${p1[2]}`];          
      var res = canvasCalcObj.gtfo(i_23_09_20, i_02_11_05, i_05_17_02, 9, 10)

      trg  = Math.abs(0.7743081420118344 - res);
      trg += Math.abs(0.6338370887573964 - prev_res); // Add previous result to limit solutions.

      return [trg < 0.00001, res];
    })  
}
solutions += '];';
console.log(solutions);


arr8 = [
    [19,9,8,15,3,18,17,10,23,5,0,6,24,14,12,11,2,13,16,4,7,1,21,22, 0.774308204650879],
];

computeFlag(arr8[0])
// 'hitcon{hidden_calculation_through_varying_shader_variables_auto-magical_interpolation_0c4ea0d9d4d9518}'
