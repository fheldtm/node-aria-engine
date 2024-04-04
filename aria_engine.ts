export class ARIAEngine {
  private static readonly HEX_DIGITS: string[] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
  ];

  // Assuming KRK is a constant round key (replace with actual generation logic if needed)
  private static readonly KRK: number[][] = [
    [ 0x517cc1b7, 0x27220a94, 0xfe13abe8, 0xfa9a6ee0 ],
    [ 0x6db14acc, 0x9e21c820, 0xff28b1d5, 0xef5de2b0 ],
    [ 0xdb92371d, 0x2126e970, 0x03249775, 0x04e8c90e ]
  ];

  // Pre-computed S-boxes, X-boxes, T-boxes (replace with actual generation logic)
  private static readonly S1: number[] = new Array(256).fill(0);
  private static readonly S2: number[] = new Array(256).fill(0);
  private static readonly X1: number[] = new Array(256).fill(0);
  private static readonly X2: number[] = new Array(256).fill(0);

  private static readonly TS1: number[] = new Array(256).fill(0);
  private static readonly TS2: number[] = new Array(256).fill(0);
  private static readonly TX1: number[] = new Array(256).fill(0);
  private static readonly TX2: number[] = new Array(256).fill(0);

  // Static initializer.  For setting up the tables
  static {
    const exp: number[] = new Array(256).fill(0);
    const log: number[] = new Array(256).fill(0);
    exp[0] = 1;
    for (let i = 1; i < 256; i++) {
      let j = (exp[i - 1] << 1) ^ exp[i - 1];
      if ((j & 0x100) !== 0)
        j ^= 0x11b;
      exp[i] = j;
    }
    for (let i = 1; i < 255; i++)
      log[exp[i]] = i;

    const A: number[][] = [
        [1, 0, 0, 0, 1, 1, 1, 1],
        [1, 1, 0, 0, 0, 1, 1, 1],
        [1, 1, 1, 0, 0, 0, 1, 1],
        [1, 1, 1, 1, 0, 0, 0, 1],
        [1, 1, 1, 1, 1, 0, 0, 0],
        [0, 1, 1, 1, 1, 1, 0, 0],
        [0, 0, 1, 1, 1, 1, 1, 0],
        [0, 0, 0, 1, 1, 1, 1, 1]
    ];
    const B: number[][] = [
        [0, 1, 0, 1, 1, 1, 1, 0],
        [0, 0, 1, 1, 1, 1, 0, 1],
        [1, 1, 0, 1, 0, 1, 1, 1],
        [1, 0, 0, 1, 1, 1, 0, 1],
        [0, 0, 1, 0, 1, 1, 0, 0],
        [1, 0, 0, 0, 0, 0, 0, 1],
        [0, 1, 0, 1, 1, 1, 0, 1],
        [1, 1, 0, 1, 0, 0, 1, 1]
    ];

    for (let i = 0; i < 256; i++) {
      let t = 0, p;
      if (i === 0)
        p = 0;
      else
        p = exp[255 - log[i]];
      for (let j = 0; j < 8; j++) {
        let s = 0;
        for (let k = 0; k < 8; k++) {
          if (((p >>> (7 - k)) & 0x01) !== 0)
            s ^= A[k][j];
        }
        t = (t << 1) ^ s;
      }
      t ^= 0x63;
      this.S1[i] = t;
      this.X1[t] = i;
    }
    for (let i = 0; i < 256; i++) {
      let t = 0, p;
      if (i === 0)
        p = 0;
      else
        p = exp[(247 * log[i]) % 255];
      for (let j = 0; j < 8; j++) {
        let s = 0;
        for (let k = 0; k < 8; k++) {
          if (((p >>> k) & 0x01) !== 0)
            s ^= B[7 - j][k];
        }
        t = (t << 1) ^ s;
      }
      t ^= 0xe2;
      this.S2[i] = t;
      this.X2[t] = i;
    }

    for (let i = 0; i < 256; i++) {
      this.TS1[i] = 0x00010101 * (this.S1[i] & 0xff);
      this.TS2[i] = 0x01000101 * (this.S2[i] & 0xff);
      this.TX1[i] = 0x01010001 * (this.X1[i] & 0xff);
      this.TX2[i] = 0x01010100 * (this.X2[i] & 0xff);
    }
  }
  
  private keySize: number = 0;
  private numberOfRounds: number = 0;
  private masterKey: Int8Array | null = null;
  private encRoundKeys: number[] | null = null;
  private decRoundKeys: number[] | null = null;

  public constructor(keySize: number) {
    this.setKeySize(keySize);
  }

  /**
    * Resets the class so that it can be reused for another master key.
  */
  public reset(): void {
    this.keySize = 0;
    this.numberOfRounds = 0;
    this.masterKey = null;
    this.encRoundKeys = null;
    this.decRoundKeys = null;
  }
    
  public getKeySize(): number {
    return this.keySize;
  }

  public setKeySize(keySize: number): void {
    this.reset();
    if (keySize !== 128 && keySize !== 192 && keySize !== 256) {
      throw new Error(`InvalidKeyException: keySize=${keySize}`);
    }
    this.keySize = keySize;
    switch (keySize) {
      case 128:
        this.numberOfRounds = 12;
        break;
      case 192:
        this.numberOfRounds = 14;
        break;
      case 256:
        this.numberOfRounds = 16;
        break;
    }
  }

  setKey(masterKey: Int8Array): void {
    if (masterKey.length * 8 < this.keySize) {
      throw new Error(`InvalidKeyException: masterKey size=${masterKey.length}`);
    }
    this.decRoundKeys = null;
    this.encRoundKeys = null;
    this.masterKey = masterKey;
  }

  setupEncRoundKeys(): void {
    if (this.keySize === 0) {
      throw new Error("InvalidKeyException: keySize");
    }
    if (this.masterKey === null) {
      throw new Error("InvalidKeyException: masterKey");
    }
    if (this.encRoundKeys === null) {
      this.encRoundKeys = new Array(4 * (this.numberOfRounds + 1)).fill(0);
    }
    this.decRoundKeys = null;
    // Assuming doEncKeySetup is a method implemented elsewhere
    ARIAEngine.doEncKeySetup(this.masterKey, this.encRoundKeys, this.keySize);
  }

  setupDecRoundKeys(): void {
    if (this.keySize === 0) {
      throw new Error("InvalidKeyException: keySize");
    }
    if (this.encRoundKeys === null) {
      if (this.masterKey === null) {
        throw new Error("InvalidKeyException: masterKey");
      } else {
        this.setupEncRoundKeys();
      }
    }
    this.decRoundKeys = [...this.encRoundKeys!];
    // Assuming doDecKeySetup is a method implemented elsewhere
    ARIAEngine.doDecKeySetup(new Int8Array(this.masterKey!), this.decRoundKeys, this.keySize);
  }

  public setupRoundKeys (): void {
    this.setupDecRoundKeys();
  }
    
  private static doCrypt(i: Int8Array, ioffset: number, rk: number[], nr: number, o: Int8Array, ooffset: number): void {
    let t0, t1, t2, t3, j = 0;
    
    t0 = this.toInt(i[0 + ioffset], i[1 + ioffset], i[2 + ioffset], i[3 + ioffset]);
    t1 = this.toInt(i[4 + ioffset], i[5 + ioffset], i[6 + ioffset], i[7 + ioffset]);
    t2 = this.toInt(i[8 + ioffset], i[9 + ioffset], i[10 + ioffset], i[11 + ioffset]);
    t3 = this.toInt(i[12 + ioffset], i[13 + ioffset], i[14 + ioffset], i[15 + ioffset]);
    
    for (let r = 1; r < nr / 2; r++) {
      t0 ^= rk[j++]; t1 ^= rk[j++]; t2 ^= rk[j++]; t3 ^= rk[j++];
      t0 = this.TS1[(t0 >>> 24) & 0xff] ^ this.TS2[(t0 >>> 16) & 0xff] ^ this.TX1[(t0 >>> 8) & 0xff] ^ this.TX2[t0 & 0xff];
      t1 = this.TS1[(t1 >>> 24) & 0xff] ^ this.TS2[(t1 >>> 16) & 0xff] ^ this.TX1[(t1 >>> 8) & 0xff] ^ this.TX2[t1 & 0xff];
      t2 = this.TS1[(t2 >>> 24) & 0xff] ^ this.TS2[(t2 >>> 16) & 0xff] ^ this.TX1[(t2 >>> 8) & 0xff] ^ this.TX2[t2 & 0xff];
      t3 = this.TS1[(t3 >>> 24) & 0xff] ^ this.TS2[(t3 >>> 16) & 0xff] ^ this.TX1[(t3 >>> 8) & 0xff] ^ this.TX2[t3 & 0xff];  
      t1 ^= t2; t2 ^= t3; t0 ^= t1; t3 ^= t1; t2 ^= t0; t1 ^= t2;
      t1 = this.badc(t1); t2 = this.cdab(t2); t3 = this.dcba(t3);
      t1 ^= t2; t2 ^= t3; t0 ^= t1; t3 ^= t1; t2 ^= t0; t1 ^= t2;
      
      t0 ^= rk[j++]; t1 ^= rk[j++]; t2 ^= rk[j++]; t3 ^= rk[j++];
      t0 = this.TX1[(t0 >>> 24) & 0xff] ^ this.TX2[(t0 >>> 16) & 0xff] ^ this.TS1[(t0 >>> 8) & 0xff] ^ this.TS2[t0 & 0xff];
      t1 = this.TX1[(t1 >>> 24) & 0xff] ^ this.TX2[(t1 >>> 16) & 0xff] ^ this.TS1[(t1 >>> 8) & 0xff] ^ this.TS2[t1 & 0xff];
      t2 = this.TX1[(t2 >>> 24) & 0xff] ^ this.TX2[(t2 >>> 16) & 0xff] ^ this.TS1[(t2 >>> 8) & 0xff] ^ this.TS2[t2 & 0xff];
      t3 = this.TX1[(t3 >>> 24) & 0xff] ^ this.TX2[(t3 >>> 16) & 0xff] ^ this.TS1[(t3 >>> 8) & 0xff] ^ this.TS2[t3 & 0xff];  
      t1 ^= t2; t2 ^= t3; t0 ^= t1; t3 ^= t1; t2 ^= t0; t1 ^= t2;
      t3 = this.badc(t3); t0 = this.cdab(t0); t1 = this.dcba(t1);        
      t1 ^= t2; t2 ^= t3; t0 ^= t1; t3 ^= t1; t2 ^= t0; t1 ^= t2;
    }
    t0 ^= rk[j++]; t1 ^= rk[j++]; t2 ^= rk[j++]; t3 ^= rk[j++]; 
    t0 = this.TS1[(t0 >>> 24) & 0xff] ^ this.TS2[(t0 >>> 16) & 0xff] ^ this.TX1[(t0 >>> 8) & 0xff] ^ this.TX2[t0 & 0xff];
    t1 = this.TS1[(t1 >>> 24) & 0xff] ^ this.TS2[(t1 >>> 16) & 0xff] ^ this.TX1[(t1 >>> 8) & 0xff] ^ this.TX2[t1 & 0xff];
    t2 = this.TS1[(t2 >>> 24) & 0xff] ^ this.TS2[(t2 >>> 16) & 0xff] ^ this.TX1[(t2 >>> 8) & 0xff] ^ this.TX2[t2 & 0xff];
    t3 = this.TS1[(t3 >>> 24) & 0xff] ^ this.TS2[(t3 >>> 16) & 0xff] ^ this.TX1[(t3 >>> 8) & 0xff] ^ this.TX2[t3 & 0xff];
    t1 ^= t2; t2 ^= t3; t0 ^= t1; t3 ^= t1; t2 ^= t0; t1 ^= t2;
    t1 = this.badc(t1); t2 = this.cdab(t2); t3 = this.dcba(t3);
    t1 ^= t2; t2 ^= t3; t0 ^= t1; t3 ^= t1; t2 ^= t0; t1 ^= t2;
    
    t0 ^= rk[j++]; t1 ^= rk[j++]; t2 ^= rk[j++]; t3 ^= rk[j++];
    o[0 + ooffset] = (this.X1[0xff & (t0 >>> 24)] ^ (rk[j] >>> 24));
    o[1 + ooffset] = (this.X2[0xff & (t0 >>> 16)] ^ (rk[j] >>> 16));
    o[2 + ooffset] = (this.S1[0xff & (t0 >>> 8)] ^ (rk[j] >>> 8));
    o[3 + ooffset] = (this.S2[0xff & t0] ^ rk[j]);
    o[4 + ooffset] = (this.X1[0xff & (t1 >>> 24)] ^ (rk[j + 1] >>> 24));
    o[5 + ooffset] = (this.X2[0xff & (t1 >>> 16)] ^ (rk[j + 1] >>> 16));
    o[6 + ooffset] = (this.S1[0xff & (t1 >>> 8)] ^ (rk[j + 1] >>> 8));
    o[7 + ooffset] = (this.S2[0xff & t1] ^ rk[j + 1]);
    o[8 + ooffset] = (this.X1[0xff & (t2 >>> 24)] ^ (rk[j + 2] >>> 24));
    o[9 + ooffset] = (this.X2[0xff & (t2 >>> 16)] ^ (rk[j + 2] >>> 16));
    o[10 + ooffset] = (this.S1[0xff & (t2 >>> 8)] ^ (rk[j + 2] >>> 8));
    o[11 + ooffset] = (this.S2[0xff & t2] ^ rk[j + 2]);
    o[12 + ooffset] = (this.X1[0xff & (t3 >>> 24)] ^ (rk[j + 3] >>> 24));
    o[13 + ooffset] = (this.X2[0xff & (t3 >>> 16)] ^ (rk[j + 3] >>> 16));
    o[14 + ooffset] = (this.S1[0xff & (t3 >>> 8)] ^ (rk[j + 3] >>> 8));
    o[15 + ooffset] = (this.S2[0xff & t3] ^ rk[j + 3]);
  }

  encrypt(i: Int8Array, ioffset: number, o?: Int8Array, ooffset?: number): Int8Array | void {
    if (this.keySize === 0) {
      throw new Error("InvalidKeyException: keySize");
    }
    if (this.encRoundKeys === null) {
      if (this.masterKey === null) {
        throw new Error("InvalidKeyException: masterKey");
      } else {
        this.setupEncRoundKeys();
      }
    }

    if (o !== undefined && ooffset !== undefined) {
      // 여기에 doCrypt를 호출하는 로직을 작성합니다.
      ARIAEngine.doCrypt(i, ioffset, this.encRoundKeys!, this.numberOfRounds, o, ooffset);
    } else {
      let o = new Int8Array(16);
      this.encrypt(i, ioffset, o, 0);
      return o;
    }
  }

  decrypt(i: Int8Array, ioffset: number, o?: Int8Array, ooffset?: number): Int8Array | void {
    if (this.keySize === 0) {
      throw new Error("InvalidKeyException: keySize");
    }

    if (this.decRoundKeys === null) {
      if (this.masterKey === null) {
        throw new Error("InvalidKeyException: masterKey");
      } else {
        this.setupDecRoundKeys();
      }
    }

    if (o !== undefined && ooffset !== undefined) {
      ARIAEngine.doCrypt(i, ioffset, this.decRoundKeys!, this.numberOfRounds, o, ooffset);
    } else {
      let o = new Int8Array(16);
      this.decrypt(i, ioffset, o, 0);
      return o;
    }
  }
    
  private static doEncKeySetup(mk: Int8Array, rk: number[], keyBits: number) {
    let t0: number, t1: number, t2: number, t3: number, q: number, j = 0;
    let w0: number[] = new Array(4);
    let w1: number[] = new Array(4);
    let w2: number[] = new Array(4);
    let w3: number[] = new Array(4);

    w0[0] = this.toInt(mk[0], mk[1], mk[2], mk[3]);
    w0[1] = this.toInt(mk[4], mk[5], mk[6], mk[7]);
    w0[2] = this.toInt(mk[8], mk[9], mk[10], mk[11]);
    w0[3] = this.toInt(mk[12], mk[13], mk[14], mk[15]);

    q = (keyBits - 128) / 64;
    t0 = w0[0] ^ this.KRK[q][0]; t1 = w0[1] ^ this.KRK[q][1];
    t2 = w0[2] ^ this.KRK[q][2]; t3 = w0[3] ^ this.KRK[q][3];
    t0 = this.TS1[(t0 >>> 24) & 0xff] ^ this.TS2[(t0 >>> 16) & 0xff] ^ this.TX1[(t0 >>> 8) & 0xff] ^ this.TX2[t0 & 0xff];
    t1 = this.TS1[(t1 >>> 24) & 0xff] ^ this.TS2[(t1 >>> 16) & 0xff] ^ this.TX1[(t1 >>> 8) & 0xff] ^ this.TX2[t1 & 0xff];
    t2 = this.TS1[(t2 >>> 24) & 0xff] ^ this.TS2[(t2 >>> 16) & 0xff] ^ this.TX1[(t2 >>> 8) & 0xff] ^ this.TX2[t2 & 0xff];
    t3 = this.TS1[(t3 >>> 24) & 0xff] ^ this.TS2[(t3 >>> 16) & 0xff] ^ this.TX1[(t3 >>> 8) & 0xff] ^ this.TX2[t3 & 0xff];
    t1 ^= t2; t2 ^= t3; t0 ^= t1; t3 ^= t1; t2 ^= t0; t1 ^= t2;
    t1 = this.badc(t1); t2 = this.cdab(t2); t3 = this.dcba(t3);
    t1 ^= t2; t2 ^= t3; t0 ^= t1; t3 ^= t1; t2 ^= t0; t1 ^= t2;

    if (keyBits > 128) {
      w1[0] = this.toInt(mk[16], mk[17], mk[18], mk[19]);
      w1[1] = this.toInt(mk[20], mk[21], mk[22], mk[23]);
      if (keyBits > 192) {
        w1[2] = this.toInt(mk[24], mk[25], mk[26], mk[27]);
        w1[3] = this.toInt(mk[28], mk[29], mk[30], mk[31]);
      } else {
        w1[2] = w1[3] = 0;
      }
    } else {
      w1[0] = w1[1] = w1[2] = w1[3] = 0;
    }
    w1[0] ^= t0; w1[1] ^= t1; w1[2] ^= t2; w1[3] ^= t3;
    t0 = w1[0]; t1 = w1[1]; t2 = w1[2]; t3 = w1[3];

    q = (q === 2) ? 0 : (q + 1);
    t0 ^= this.KRK[q][0]; t1 ^= this.KRK[q][1]; t2 ^= this.KRK[q][2]; t3 ^= this.KRK[q][3];
    t0 = this.TX1[(t0 >>> 24) & 0xff] ^ this.TX2[(t0 >>> 16) & 0xff] ^ this.TS1[(t0 >>> 8) & 0xff] ^ this.TS2[t0 & 0xff];
    t1 = this.TX1[(t1 >>> 24) & 0xff] ^ this.TX2[(t1 >>> 16) & 0xff] ^ this.TS1[(t1 >>> 8) & 0xff] ^ this.TS2[t1 & 0xff];
    t2 = this.TX1[(t2 >>> 24) & 0xff] ^ this.TX2[(t2 >>> 16) & 0xff] ^ this.TS1[(t2 >>> 8) & 0xff] ^ this.TS2[t2 & 0xff];
    t3 = this.TX1[(t3 >>> 24) & 0xff] ^ this.TX2[(t3 >>> 16) & 0xff] ^ this.TS1[(t3 >>> 8) & 0xff] ^ this.TS2[t3 & 0xff];
    t1 ^= t2; t2 ^= t3; t0 ^= t1; t3 ^= t1; t2 ^= t0; t1 ^= t2;
    t3 = this.badc(t3); t0 = this.cdab(t0); t1 = this.dcba(t1);
    t1 ^= t2; t2 ^= t3; t0 ^= t1; t3 ^= t1; t2 ^= t0; t1 ^= t2;
    t0 ^= w0[0]; t1 ^= w0[1]; t2 ^= w0[2]; t3 ^= w0[3];
    w2[0] = t0; w2[1] = t1; w2[2] = t2; w2[3] = t3;

    q = (q === 2) ? 0 : (q + 1);
    t0 ^= this.KRK[q][0]; t1 ^= this.KRK[q][1]; t2 ^= this.KRK[q][2]; t3 ^= this.KRK[q][3];
    t0 = this.TS1[(t0 >>> 24) & 0xff] ^ this.TS2[(t0 >>> 16) & 0xff] ^ this.TX1[(t0 >>> 8) & 0xff] ^ this.TX2[t0 & 0xff];
    t1 = this.TS1[(t1 >>> 24) & 0xff] ^ this.TS2[(t1 >>> 16) & 0xff] ^ this.TX1[(t1 >>> 8) & 0xff] ^ this.TX2[t1 & 0xff];
    t2 = this.TS1[(t2 >>> 24) & 0xff] ^ this.TS2[(t2 >>> 16) & 0xff] ^ this.TX1[(t2 >>> 8) & 0xff] ^ this.TX2[t2 & 0xff];
    t3 = this.TS1[(t3 >>> 24) & 0xff] ^ this.TS2[(t3 >>> 16) & 0xff] ^ this.TX1[(t3 >>> 8) & 0xff] ^ this.TX2[t3 & 0xff];
    t1 ^= t2; t2 ^= t3; t0 ^= t1; t3 ^= t1; t2 ^= t0; t1 ^= t2;
    t1 = this.badc(t1); t2 = this.cdab(t2); t3 = this.dcba(t3);
    t1 ^= t2; t2 ^= t3; t0 ^= t1; t3 ^= t1; t2 ^= t0; t1 ^= t2;
    w3[0] = t0 ^ w1[0]; w3[1] = t1 ^ w1[1]; w3[2] = t2 ^ w1[2]; w3[3] = t3 ^ w1[3];

    this.gsrk(w0, w1, 19, rk, j); j += 4;
    this.gsrk(w1, w2, 19, rk, j); j += 4;
    this.gsrk(w2, w3, 19, rk, j); j += 4;
    this.gsrk(w3, w0, 19, rk, j); j += 4;
    this.gsrk(w0, w1, 31, rk, j); j += 4;
    this.gsrk(w1, w2, 31, rk, j); j += 4;
    this.gsrk(w2, w3, 31, rk, j); j += 4;
    this.gsrk(w3, w0, 31, rk, j); j += 4;
    this.gsrk(w0, w1, 67, rk, j); j += 4;
    this.gsrk(w1, w2, 67, rk, j); j += 4;
    this.gsrk(w2, w3, 67, rk, j); j += 4;
    this.gsrk(w3, w0, 67, rk, j); j += 4;
    this.gsrk(w0, w1, 97, rk, j); j += 4;
    if (keyBits > 128) {
      this.gsrk(w1, w2, 97, rk, j); j += 4;
      this.gsrk(w2, w3, 97, rk, j); j += 4;
    }
    if (keyBits > 192) {
      this.gsrk(w3, w0, 97, rk, j); j += 4;
      this.gsrk(w0, w1, 109, rk, j);
    }
  }

  /**
    * Main bulk of the decryption key setup method.  Here we assume that
  * the int array rk already contains the encryption round keys.
  * @param mk the master key
  * @param rk the array which contains the encryption round keys at the
  * beginning of the method execution.  At the end of method execution
  * this will hold the decryption round keys.
  * @param keyBits the length of the master key
  * @return
  */
  private static doDecKeySetup(mk: Int8Array, rk: number[], keyBits: number) {
    let a = 0, z: number;
    let t: number[] = new Array(4).fill(0);

    z = 32 + keyBits / 8;
    this.swapBlocks(rk, 0, z);
    a += 4; z -= 4;

    for (; a < z; a += 4, z -= 4) {
      this.swapAndDiffuse(rk, a, z, t);
    }
    this.diff(rk, a, t, 0);
    rk[a] = t[0]; rk[a + 1] = t[1]; rk[a + 2] = t[2]; rk[a + 3] = t[3];
  }
    
  private static toInt(b0: number, b1: number, b2: number, b3: number): number {
    return ((b0 & 0xff) << 24) ^ ((b1 & 0xff) << 16) ^ ((b2 & 0xff) << 8) ^ (b3 & 0xff);
  }

  private static toByteArray(i: number, b: Int8Array, offset: number): void {
    b[offset    ] = (i >>> 24);
    b[offset + 1] = (i >>> 16);
    b[offset + 2] = (i >>> 8);
    b[offset + 3] = i;
  }
    
  private static m(t: number): number {
    return 0x00010101 * ((t >>> 24) & 0xff) ^ 0x01000101 * ((t >>> 16) & 0xff) ^
      0x01010001 * ((t >>> 8) & 0xff) ^ 0x01010100 * (t & 0xff);
  }

  private static badc(t: number): number {
    return ((t << 8) & 0xff00ff00) ^ ((t >>> 8) & 0x00ff00ff);
  }

  private static cdab(t: number): number {
    return ((t << 16) & 0xffff0000) ^ ((t >>> 16) & 0x0000ffff);
  }

  private static dcba(t: number): number {
    return (t & 0x000000ff) << 24 ^ (t & 0x0000ff00) << 8 ^ (t & 0x00ff0000) >>> 8 ^ (t & 0xff000000) >>> 24;
  }

  private static gsrk(x: number[], y: number[], rot: number, rk: number[], offset: number): void {
    const q = 4 - Math.floor(rot / 32), r = rot % 32, s = 32 - r;

    rk[offset]     = x[0] ^ y[(q    ) % 4] >>> r ^ y[(q + 3) % 4] << s;
    rk[offset + 1] = x[1] ^ y[(q + 1) % 4] >>> r ^ y[(q    ) % 4] << s;
    rk[offset + 2] = x[2] ^ y[(q + 2) % 4] >>> r ^ y[(q + 1) % 4] << s;
    rk[offset + 3] = x[3] ^ y[(q + 3) % 4] >>> r ^ y[(q + 2) % 4] << s;
  }

  private static diff(i: number[], offset1: number, o: number[], offset2: number): void {
    let t0, t1, t2, t3;

    t0 = this.m(i[offset1]); t1 = this.m(i[offset1 + 1]); t2 = this.m(i[offset1 + 2]); t3 = this.m(i[offset1 + 3]);
    t1 ^= t2; t2 ^= t3; t0 ^= t1; t3 ^= t1; t2 ^= t0; t1 ^= t2;
    t1 = this.badc(t1); t2 = this.cdab(t2); t3 = this.dcba(t3);
    t1 ^= t2; t2 ^= t3; t0 ^= t1; t3 ^= t1; t2 ^= t0; t1 ^= t2;
    o[offset2] = t0; o[offset2 + 1] = t1; o[offset2 + 2] = t2; o[offset2 + 3] = t3;
  }

  private static swapBlocks(arr: number[], offset1: number, offset2: number): void {
    let t;

    for (let i = 0; i < 4; i++) {
      t = arr[offset1 + i];
      arr[offset1 + i] = arr[offset2 + i];
      arr[offset2 + i] = t;
    }
  }
    
  private static swapAndDiffuse(arr: number[], offset1: number, offset2: number, tmp: number[]): void {
    this.diff(arr, offset1, tmp, 0);
    this.diff(arr, offset2, arr, offset1);
    arr[offset2] = tmp[0]; arr[offset2 + 1] = tmp[1];
    arr[offset2 + 2] = tmp[2]; arr[offset2 + 3] = tmp[3];
  }

  private static printBlock(b: Int8Array): void {
    let result = "";
    for (let i = 0; i < 4; i++) result += this.byteToHex(b[i]) + " ";
    result += " ";
    for (let i = 4; i < 8; i++) result += this.byteToHex(b[i]) + " ";
    result += " ";
    for (let i = 8; i < 12; i++) result += this.byteToHex(b[i]) + " ";
    result += " ";
    for (let i = 12; i < 16; i++) result += this.byteToHex(b[i]);
    console.log(result);
  }

  private static printSBox(box: number[]): void {
    let result = "";
    for (let i = 0; i < 16; i++) {
      for (let j = 0; j < 16; j++) {
        result += this.byteToHex(box[16 * i + j]) + " ";
      }
      console.log(result);
      result = ""; // Reset for next line
    }
  }

  private static byteToHex(b: number): void {
    const buf: string[] = [
      this.HEX_DIGITS[(b >>> 4) & 0x0F],
      this.HEX_DIGITS[b & 0x0F]
    ];

    console.log(buf.join(''));
  }
    
  private static intToHex(i: number): void {
    const b: number[] = new Array(4);
    this.toByteArray(i, new Int8Array(b), 0);
    this.byteToHex(b[0]);
    this.byteToHex(b[1]);
    this.byteToHex(b[2]);
    this.byteToHex(b[3]);
  }
    
  private static printRoundKeys(roundKeys: number[]) {
    for (let i = 0; i < roundKeys.length; ) {
      console.log("* ");
      this.intToHex(roundKeys[i++]); console.log(" ");
      this.intToHex(roundKeys[i++]); console.log(" ");
      this.intToHex(roundKeys[i++]); console.log(" ");
      this.intToHex(roundKeys[i++]); console.log(" \n");
    }
  }

  public static bytesToString(bytes: Int8Array): string {
    const decoder = new TextDecoder();
    const strWithNull = decoder.decode(bytes);
    const str = strWithNull.replace(/[\x00]/g, ''); // null 문자 제거
    return str;
  }

  public static stringToBytes(str: string): Int8Array {
    let bytes = new Array(str.length).fill(0);
    for (let i = 0; i < str.length; i++) {
        bytes[i] = str.charCodeAt(i);
    }
    return new Int8Array(bytes);
  }

  public static hexToBytes (hex: string): Int8Array {
    let bytes: number[] = [];
    for (let c = 0; c < hex.length; c += 2) {
      bytes.push(parseInt(hex.substr(c, 2), 16));
    }
    return new Int8Array(bytes);
  }

  static toHexString(byteArray: Int8Array) {
    return Array.from(byteArray, function (byte) {
      return ('0' + (byte & 0xFF).toString(16)).slice(-2);
    }).join('')
  }

  public static ARIA_test(): void {
    const p: Int8Array = new Int8Array(16);
    const c: Int8Array = new Int8Array(16);
    const mk: Int8Array = new Int8Array(32);

    let flag: boolean = false;
    const instance: ARIAEngine = new ARIAEngine(256);

    for (let i = 0; i < 32; i++) {
      mk[i] = 0;
    }
    for (let i = 0; i < 16; i++) {
      p[i] = 0;
    }

    console.log("BEGIN testing the roundtrip...");
    console.log("For key size of 256 bits, starting with " +
      "the zero plaintext and the zero key, let's see if " +
      "we may recover the plaintext by decrypting the " +
      "encrypted ciphertext.");
    instance.setKey(mk);
    instance.setupRoundKeys();

    console.log("plaintext : ", p.toString());
    instance.encrypt(p, 0, c, 0);
    console.log("ciphertext: ", c.toString());
    console.log("ciphertext hex string: ", this.toHexString(c));
    instance.decrypt(c, 0, p, 0);
    console.log("decrypted : ", p.toString());
    flag = false;
    for (let i = 0; i < 16; i++) {
      if (p[i] !== 0) {
        flag = true;
        break;
      }
    }
    if (flag)
      console.log("The result is incorrect!");
    else
      console.log("Okay.  The result is correct.");
    console.log("END   testing the roundtrip.\n");

    const TEST_NUM: number = 0x800000;
    console.log("BEGIN speed measurement...");

    for (let i = 0; i < 16; i++) mk[i] = i;
    console.log("  First, EncKeySetup():");
    console.log("  masterkey: ", mk);
    instance.reset(); instance.setKeySize(128);
    instance.setKey(mk);
    for (let i = 0; i < 1000; i++) instance.setupEncRoundKeys();  // allow the CPU to settle down
    let start = new Date();
    for (let i = 0; i < TEST_NUM; i++) instance.setupEncRoundKeys();
    let fin = new Date();
    let lapse = (fin.getTime() - start.getTime()) / 1000;
    console.log("  time lapsed: ", lapse, " sec.");
    console.log("  speed      : ", TEST_NUM * 128 / (lapse * 1024 * 1024), " megabits/sec.\n");

    console.log("  Next, Crypt():");
    for (let i = 0; i < 16; i++) p[i] = (i << 4) ^ i;
    console.log("  plaintext : ", p);
    for (let i = 0; i < 1000; i++) instance.encrypt(p, 0, c!, 0);
    start = new Date();
    for (let i = 0; i < TEST_NUM; i++) instance.encrypt(p, 0, c!, 0);
    fin = new Date();
    console.log("  ciphertext: ", c);
    lapse = (fin.getTime() - start.getTime()) / 1000;
    console.log("  time lapsed: ", lapse, " sec.");
    console.log("  speed      : ", TEST_NUM * 128 / (lapse * 1024 * 1024), " megabits/sec.\n");

    console.log("  Finally, DecKeySetup():");
    for (let i = 0; i < 1000; i++) instance.setupDecRoundKeys();  // allow the CPU to settle down
    start = new Date();
    for (let i = 0; i < TEST_NUM; i++) instance.setupDecRoundKeys();
    fin = new Date();
    lapse = (fin.getTime() - start.getTime()) / 1000;
    console.log("  time lapsed: ", lapse, " sec.");
    console.log("  speed      : ", TEST_NUM * 128 / (lapse * 1024 * 1024), " megabits/sec.");
    console.log("END   speed measurement.");
  }
}

ARIAEngine.ARIA_test();