var protocols = {
  IPv4: 0x0800,
  IPv6: 0x86DD,
  ARP: 0x0806,
  ICMP: 0x0001,
  TCP: 0x0006,
  UDP: 0x0011,
  DHCP: 68,
  DNS: 53,
}

class Address extends EventTarget {
  #IP = undefined;
  #MAC = undefined;
  #domain = undefined;
  constructor(IP, MAC) {
    super();
    if (!(IP === undefined || (IP.match(/^(?:[0-9]{1,3}(?:\.|$)){4}/)||false) && IP.split(".").every((i)=>0<=parseInt(i)&&parseInt(i)<=255))) {
      throw "Invalid IP address";
    } else if (!(MAC === undefined || MAC.match(/^(([0-9]|[a-f]|[A-F]){2}[:|-]?){6}(?<!:|-)$/)||false)) {
      throw "Invalid MAC address";
    }
    this.#IP = IP || undefined;
    this.#MAC = MAC || undefined;
  }
  get IP() {
    return this.#IP;
  }
  set IP(value) {
    if (!(value === undefined || (value.match(/^(?:[0-9]{1,3}(?:\.|$)){4}/)||false) && value.split(".").every((i)=>0<=parseInt(i)&&parseInt(i)<=255))) {
      throw "Invalid IP address";
    }
    this.#IP = value || undefined;
  }
  get MAC() {
    return this.#MAC;
  }
  set MAC(value) {
    if (!(value === undefined || value.match(/^(([0-9]|[a-f]|[A-F]){2}[:|-]?){6}(?<!:|-)$/)||false)) {
      throw "Invalid MAC address";
    }
    this.#MAC = value || undefined;
  }
}

class Certificate {
  constructor() {
  }
  static async fromFile(file) {
    var binaries;
    if (file.name.match(/\.(?:der|DER)$/)) {
      await file.arrayBuffer().then((buffer)=>{
        binaries = [new Uint8Array(buffer)];
      });
    } else if (file.name.match(/\.(?:pem|PEM)$/)) {
      await file.text().then((text)=>{
        binaries = [...text.matchAll(/-+BEGIN CERTIFICATE-+\n(?<base64>(?:[0-9]|[a-z]|[A-Z]|[/+=]|\n)+?)\n-+END CERTIFICATE-+(?=\n)/g)].map((i)=>new Uint8Array([...atob(i.groups.base64.replace("\n", ""))].map((i)=>i.charCodeAt())));
      });
    } else { throw "Unknown file type"; }
    console.log(binaries);
    var results = [];
    for (let bin of binaries) {
      results.push(this.fromBinary(bin));
    }
    return results;
  }
  static fromBinary(binary) {
    let bin = [...binary];
    if (true) {
      console.log(bin);
      var result = {tag:0, class:0, length: 0, value:undefined, root:undefined};
      var current = result;
      var ranges = [[0, bin.length-1]];
      for (let i=0; i < bin.length; i++) {
        current.class = bin[i] >> 6;
        if (bin[i]%32 == 31) {
          current.tag = (bin[i]&32) >> 5;
          while (true) {
            i += 1;
            current.tag = (current.tag << 7) + bin[i]&127;
            if (!(bin[i]&128)) { break; }
          }
        } else {
          current.tag = bin[i] & 63;
        }
        i += 1;
        if (bin[i] & 128) {
          if (bin[i] & 127 == 0) {
            current.length = undefined;
          } else {
            current.length = bin.slice(i+1, i+(bin[i]&127)+1).reduce((s, i)=>i+(s<<8));
            if (current.length < 0) {
                console.log(current);
              throw "ああああああああああああああああああああああああ";
            }
            i += (bin[i] & 127);
          }
        } else {
          current.length = bin[i];
        }
        if (current.tag&32) {
          current.value = [{tag:0, value:undefined, root:current}];
          ranges.push([i+1, current.length==undefined?undefined:i+current.length]);
          current = current.value[0];
          continue;
        } else {
          if (current.length == undefined) {
            current.value = bin.slice(i+1, bin.indexOf(0, i+1));
            i+= current.value.length;
          } else if (current.length > 0) {
            current.value = bin.slice(i+1, i+current.length+1);
            i += current.length;
          }
          console.log(current.tag&31);
          if ((current.tag&31) == 1) {
            current.value = current.value.reduce((s, i)=>s+i) > 0;
          } else if ((current.tag&31) == 2) {
            //console.log(current.value);
            if (current.value.length <= 4) {
              current.value = current.value.reduce((s, i)=>i+(s<<8));
            } else {
              current.value = BigInt("0x"+current.value.reduce((s, i)=>s+i.toString(16), ""));
              if (current.value <= Number.MAX_SAFE_INTEGER && current.value >= Number.MIN_SAFE_INTEGER) {
                current.value = Number(current.value);
              }
            }
          } else if ((current.tag&31) == 3) {
            current.value = current.value.reduce((s, i)=>s+String.fromCharCode(i), "");
          } else if ((current.tag&31) == 4) {
            current.value = current.value.reduce((s, i)=>s+String.fromCharCode(i), "");
          } else if ((current.tag&31) == 5) {
            current.value = null;
          } else if ((current.tag&31) == 6) {
            console.log(current.value);
            current.value = [...current.value].reduce((s, i)=>i&0x80?[...s.slice(0, -1), ((s.at(-1)||0)<<8)+(i-0x80)]:[...s.slice(0, -1), ((s.at(-1)||0)*128)+i, 0], []).slice(0, -1).map((i, index)=>{return index==0?[Math.min(2, Math.floor(i/40)), i-Math.min(2, Math.floor(i/40))*40]:[i]}).flat();
          } else if ((current.tag&31) == 7) {
            current.value = current.value.reduce((s, i)=>s+String.fromCharCode(i), "");
          } else if ((current.tag&31) == 8) {
            //current.value = null; 外部とかいうやつ
          } else if ((current.tag&31) == 9) {
            if (current.length == 1 && (current.value[0] == 0x40 || current.value[0] == 0x41)) {
              current.value = Infinity * (current.value[0]&1?(-1):1);
            } else if (current.length == 1 && current.value[0] == 0) {
              current.value = 0;
            } else {
              // 小数めんどいから一旦放置
            }
          } else if ([12, 18, 19, 20, 22].includes((current.tag&31))) {
            current.value = String.fromCharCode(...current.value);
          } else if ((current.tag&31) == 23) {
            current.value = new Date(current.value.reduce((s,i)=>s+String.fromCharCode(i), "").replace(/^(?<year>\d{2})(?<month>\d{2})(?<day>\d{2})(?<hour>\d{2})(?<minute>\d{2})(?<second>\d{2}){0,1}(?:Z|(?<offset>[+|-]\d{4}))$/, (match, yy, mm, dd, hh, MM, ss, offset)=>`20${yy}/${mm}/${dd} ${hh}:${MM}:${ss||"00"}${offset||""} GMT`));
          } else {}
          console.log(current);
          if (current.root != undefined && current.root.tag&32) {
            while (ranges.length > 0 && ranges.at(-1)[1] <= i) {
              current = current.root;
              ranges.pop();
              console.log(ranges.length);
            }
            if (ranges.length == 0) { break; }
            current.root.value.push({tag:0, value:undefined, root:current.root});
            current = current.root.value.at(-1);
            continue;
          } else {
            throw "root can be only a set or a sequence";
          }
        }
      }
      var cert = new this();
      cert.version = result.value[0].value[0].value[0].value+1;
      cert.serialNumber = result.value[0].value[1].value;
      cert.signatureAlgorithm = result.value[2].value
      //results.push([result, cert]);
    }
    return cert;
  }
}


class NetworkFrame {
  constructor() {
    this.header = {};
    this.data = null;
  }
  build() {
    return new Uint8Array();
  }
  static fromBinary(binary) {
    throw "Not defined";
  }
}

class EthernetFrame extends NetworkFrame {
  constructor(desMAC, srcMAC, protocol) {
    super();
    this.header.desMAC = desMAC;
    this.header.srcMAC = srcMAC;
    this.header.protocol = protocol;
  }
  build() {
    var rawHeader = [];
    var rawData = [];
    if (!this.header.desMAC.match(/^(([0-9]|[a-f]|[A-F]){2}[:|-]?){6}(?<!:|-)$/)||false) {
      throw "destination MAC address is wrong style";
    } else if (!this.header.srcMAC.match(/^(([0-9]|[a-f]|[A-F]){2}[:|-]?){6}(?<!:|-)$/)||false) {
      throw "source MAC address is wrong style";
    } else {
      rawHeader.push(...this.header.desMAC.split(/(?<=^(?:(?:[0-9]|[a-f]|[A-F]){2}[:|-]?)+)[:|-]?/).map((i)=>{return parseInt(i, 16)}));
      rawHeader.push(...this.header.srcMAC.split(/(?<=^(?:(?:[0-9]|[a-f]|[A-F]){2}[:|-]?)+)[:|-]?/).map((i)=>{return parseInt(i, 16)}));
    }

    if (this.header.protocol == 0x0800 || (typeof this.header.protocol == "string" && (this.header.protocol.toLowerCase() == "ipv4" || parseInt(this.header.protocol, 16) == 0x0800))) {
      rawHeader.push(0x08, 0x00);
    } else if (this.header.protocol == 0x86DD || (typeof this.header.protocol == "string" && (this.header.protocol.toLowerCase() == "ipv6" || parseInt(this.header.protocol, 16) == 0x86DD))) {
      rawHeader.push(0x86, 0xDD);
    } else if (this.header.protocol == 0x0806 || (typeof this.header.protocol == "string" && (this.header.protocol.toLowerCase() == "arp" || parseInt(this.header.protocol, 16) == 0x0806))) {
      rawHeader.push(0x08, 0x06);
    } else {
      throw "unknown protocol type";
    }
    // data
    if (this.data == undefined || this.data == null) {
      ;
    } else if (NetworkFrame.prototype.isPrototypeOf(this.data)) {
      rawData.push(...(this.data.build()||[]));
    } else if (Uint8Array.prototype.isPrototypeOf(this.data)) {
      rawData.push(...this.data);
    } else if (Array.prototype.isPrototypeOf(this.data) && this.data.every((i)=>{return NetworkFrame.prototype.isPrototypeOf(i)||Uint8Array.prototype.isPrototypeOf(i)})) {
      for (let i of this.data) {
        if (NetworkFrame.prototype.isPrototypeOf(i)) {
          rawData.push(...(i.build()||[]));
        } else {
          rawData.push(...i);
        }
      }
    } else {
      throw "invalid data";
    }
    /* if (rawHeader.length + rawData.length < 60) {
      for (let i = 0; rawHeader.length + rawData.length < 60; i++) {
        rawData.push(0);
      }
    }*/
    return new Uint8Array([...rawHeader, ...rawData]);
  }

  static fromBinary(binary) {
    binary = [...binary];
    var res = new this();
    res.header.desMAC = binary.slice(0, 6).map((i)=>i.toString(16).padStart(2, "0")).join(":");
    res.header.srcMAC = binary.slice(6, 12).map((i)=>i.toString(16).padStart(2, "0")).join(":");
    res.header.protocol = binary.slice(12, 14).reduce((i, i2)=>(i << 8)|i2, 0);
    /* try {
      if (res.header.protocol == 0x0800) {
        res.data = IPFrame.fromBinary(binary.slice(14));
      } else if (res.header.protocol == 0x08dd) {
        throw "IPv6 is not supported"; //res.data = IPFrame.fromBinary(binary.slice(14));
      } else if (res.header.protocol == 0x0806) {
        res.data = ARPFrame.fromBinary(binary.slice(14));
      } else {
        throw "Unknown protocol";
      }
    } catch { */
    res.data = new Uint8Array(binary.slice(14));
    //}
    return res;
  }

  name = "Ethernet";
}

class ARPFrame extends NetworkFrame {
  constructor(protocol, hardwareSize, protocolSize, opcode, srcMAC, srcIP, desMAC, desIP) {
    super();
    this.header.protocol = protocol;
    this.header.hardwareSize = hardwareSize;
    this.header.protocolSize = protocolSize;
    this.header.opcode = opcode;
    this.header.srcMAC = srcMAC;
    this.header.srcIP = srcIP;
    this.header.desMAC = desMAC;
    this.header.desIP = desIP;
  }

  build() {
    var rawHeader = [];
    rawHeader.push(0);
    rawHeader.push(0x01); //ハードウェアはEthernetだから1
    if (this.header.protocol == 0x0800 || (typeof this.header.protocol == "string" && (this.header.protocol.toLowerCase() == "ipv4" || parseInt(this.header.protocol, 16) == 0x0800))) {
      rawHeader.push(0x08, 0x00);
    } else {
      throw "unknown protocol type";
    }
    if (this.header.hardwareSize == 6) {
      rawHeader.push(6);
    } else {
      throw this.name + ": " + "invalid hardware size";
    }
    if (this.header.protocolSize == 4) {
      rawHeader.push(4);
    } else {
      throw this.name + ": " + "invalid protocol size";
    }
    if ((typeof this.header.opcode == "number" && this.header.opcode == 0x0001) || (typeof this.header.opcode == "string" && this.header.opcode.toLowerCase() == "request")) {
      rawHeader.push(0x00, 0x01);
    } else if ((typeof this.header.opcode == "number" && this.header.opcode == 0x0002) || (typeof this.header.opcode == "string" && this.header.opcode.toLowerCase() == "reply")) {
      rawHeader.push(0x00, 0x02);
    } else {
      throw this.name + ": " + "unknown opcode";
    }
    if (!this.header.srcMAC.match(/^(([0-9]|[a-f]|[A-F]){2}[:|-]?){6}(?<!:|-)$/)||false) {
      throw this.name + ": source MAC address is wrong style";
    } else if (!this.header.srcIP.split(".").map((i)=>parseInt(i)).every((i)=>0<=i&&i<=255)) {
      throw this.name + ": source IP address is wrong style";
    } else if (!this.header.desMAC.match(/^(([0-9]|[a-f]|[A-F]){2}[:|-]?){6}(?<!:|-)$/)||false) {
      throw this.name + ": destination MAC address is wrong style";
    } else if (!this.header.desIP.split(".").map((i)=>parseInt(i)).every((i)=>0<=i&&i<=255)) {
      throw this.name + ": destination IP address is wrong style";
    } else {
      rawHeader.push(...this.header.srcMAC.split(/(?<=^(?:(?:[0-9]|[a-f]|[A-F]){2}[:|-]?)+)[:|-]?/).map((i)=>{return parseInt(i, 16)}));
      rawHeader.push(...this.header.srcIP.split(".").map((i)=>parseInt(i)));
      rawHeader.push(...this.header.desMAC.split(/(?<=^(?:(?:[0-9]|[a-f]|[A-F]){2}[:|-]?)+)[:|-]?/).map((i)=>{return parseInt(i, 16)}));
      rawHeader.push(...this.header.desIP.split(".").map((i)=>parseInt(i)));
    }
    return new Uint8Array(rawHeader);
  }

  static fromBinary(binary) {
    binary = [...binary];
    var res = new this();
    res.header.hardware = binary.slice(0, 2).reduce((i, i2)=>(i << 8)|i2, 0);
    res.header.protocol = binary.slice(2, 4).reduce((i, i2)=>(i << 8)|i2, 0);
    res.header.hardwareSize = binary[4];
    res.header.protocolSize = binary[5];
    res.header.opcode = binary.slice(6, 8).reduce((i, i2)=>(i << 8)|i2, 0);
    res.header.srcMAC = binary.slice(8, 14).map((i)=>i.toString(16).padStart(2, "0")).join(":");
    res.header.srcIP = binary.slice(14, 18).join(".");
    res.header.desMAC = binary.slice(18, 24).map((i)=>i.toString(16).padStart(2, "0")).join(":");
    res.header.desIP = binary.slice(24, 28).join(".");
    return res;
  }

  name = "ARP";
}

class IPFrame extends NetworkFrame {
  constructor(version, serviceType, identification, flag, flagOffset, life, protocol, srcIP, desIP, option) {
    super();
    this.header.version = version;
    this.header.serviceType = serviceType;
    this.header.identification = identification;
    this.header.flag = flag;
    this.header.flagOffset = flagOffset;
    this.header.life = life;
    this.header.protocol = protocol;
    this.header.srcIP = srcIP;
    this.header.desIP = desIP;
    this.header.option = option;
  }
  build() {
    var rawHeader = [];
    var rawData = [];
    rawHeader.push(this.header.version << 4)
    //あとでヘッダ長を上書き
    rawHeader.push(this.header.serviceType);
    rawHeader.push(0x00, 0x00); //あとでパケット長を上書き
    rawHeader.push(this.header.identification >> 8, this.header.identification & 0xff);
    rawHeader.push((this.header.flag << 5)|(this.header.flagOffset >> 8), this.header.flagOffset & 0xff);
    rawHeader.push(this.header.life);
    if ((typeof this.header.protocol == "number" && this.header.protocol == 0x0001) || (typeof this.header.protocol == "string" && this.header.protocol.toLowerCase() == "icmp")) {
      rawHeader.push(0x01);
    } else if ((typeof this.header.protocol == "number" && this.header.protocol == 0x0006) || (typeof this.header.protocol == "string" && this.header.protocol.toLowerCase() == "tcp")) {
      rawHeader.push(0x06);
    } else if ((typeof this.header.protocol == "number" && this.header.protocol == 0x0011) || (typeof this.header.protocol == "string" && this.header.protocol.toLowerCase() == "udp")) {
      rawHeader.push(0x11);
    } else {
      throw this.name + ": " + "unknown protocol";
    }
    rawHeader.push(0x00, 0x00); //あとでチェックサムを上書き
    if (!this.header.srcIP.split(".").map((i)=>parseInt(i)).every((i)=>0<=i&&i<=255)) {
      throw this.name + ": source IP address is wrong style";
    } else if (!this.header.desIP.split(".").map((i)=>parseInt(i)).every((i)=>0<=i&&i<=255)) {
      throw this.name + ": destination IP address is wrong style";
    } else {
      rawHeader.push(...this.header.srcIP.split(".").map((i)=>parseInt(i)));
      rawHeader.push(...this.header.desIP.split(".").map((i)=>parseInt(i)));
    }
    //rawHeader.push() // オプションは未実装
    //パディング
    for (let i = 0; rawHeader.length % 4 > 0; i++) {
      rawHeader.push(0x00);
    }
    rawHeader.splice(0, 1, rawHeader[0] | (rawHeader.length / 4));
    // data
    if (this.data == undefined || this.data == null) {
      ;
    } else if (NetworkFrame.prototype.isPrototypeOf(this.data)) {
      rawData.push(...(this.data.build()||[]));
    } else if (Uint8Array.prototype.isPrototypeOf(this.data)) {
      rawData.push(...this.data);
    } else if (Array.prototype.isPrototypeOf(this.data) && this.data.every((i)=>{return NetworkFrame.prototype.isPrototypeOf(i)||Uint8Array.prototype.isPrototypeOf(i)})) {
      for (let i of this.data) {
        if (NetworkFrame.prototype.isPrototypeOf(i)) {
          rawData.push(...(i.build()||[]));
        } else {
          rawData.push(...i);
        }
      }
    } else {
      throw "invalid data";
    }
    rawHeader.splice(2, 2, (rawHeader.length + rawData.length) >> 8, (rawHeader.length + rawData.length) & 0xff);
    // checksum
    var checksum = 0;
    for (let i = 0; i < rawHeader.length; i += 2) {
      checksum += ((rawHeader[i] << 8) + (rawHeader[i+1]||0));
    }
    checksum = ((checksum & 0xffff) + (checksum >> 16));
    checksum = checksum ^ 0xffff;
    rawHeader.splice(10, 2, checksum >> 8, checksum & 0xff);
    return new Uint8Array([...rawHeader, ...rawData]);
  }
  static fromBinary(binary) {
    binary = [...binary];
    var res = new this();
    res.header.version = binary[0] >> 4;
    res.header.serviceType = binary[1];
    res.header.identification = binary.slice(4, 5).reduce((i, i2)=>(i << 8)|i2, 0);
    res.header.flag = binary[6] >> 5;
    res.header.flagOffset = ((binary[6] & 0x1f) << 8) | binary[7];
    res.header.life = binary[8];
    res.header.protocol = binary[9]
    res.header.srcIP = binary.slice(12, 16).join(".");
    res.header.desIP = binary.slice(16, 20).join(".");
    /* try {
      if (res.header.protocol == 0x06) {
        res.data = TCPFrame.fromBinary(binary.slice(20));
        res.data.header.srcIP = res.header.srcIP;
        res.data.header.desIP = res.header.desIP;
      } else if (res.header.protocol == 0x11) {
        res.data = UDPFrame.fromBinary(binary.slice(20));
        res.data.header.srcIP = res.header.srcIP;
        res.data.header.desIP = res.header.desIP;
      } else {
        throw "Unknown protocol";
      }
    } catch { */
    res.data = new Uint8Array(binary.slice(20));
    //}
    return res;
  }
  name = "IP"
}

class ICMPFrame extends NetworkFrame {
  constructor(type, code) {
    super();
    this.header.type = type;
    this.header.code = code;
  }
  build() {
    var rawHeader = [];
    var rawData = [];
    rawHeader.push(this.header.type);
    rawHeader.push(this.header.code);
    rawHeader.push(0x00, 0x00); //あとでチェックサムを上書き
    rawData.push(...(this.data||[]));
    // checksum
    var checksum = 0;
    var rawAll = [...rawHeader, ...rawData];
    for (let i = 0; i < rawAll.length; i += 2) {
      checksum += (rawAll[i] << 8) + (rawAll[i+1]||0);
    }
    checksum = ((checksum & 0xffff) + (checksum >> 16)) ^ 0xffff;
    rawAll.splice(2, 2, checksum >> 8, checksum & 0xff);
    return new Uint8Array(rawAll);
  }
  static fromBinary(binary) {
    binary = [...binary];
    var res = new this();
    this.header.type = binary[0];
    this.header.code = binary[1];
    this.data = binary.slice(4) || [];
    return res;
  }
  name = "ICMP"
}

class TCPFrame extends NetworkFrame {
  constructor(srcIP, srcPort, desIP, desPort, sequence, ackNum, control, options, windowSize) {
    super();
    this.header.srcIP = srcIP;
    this.header.srcPort = srcPort;
    this.header.desIP = desIP;
    this.header.desPort = desPort;
    this.header.sequence = sequence;
    this.header.ackNum = ackNum;
    this.header.control = control;
    this.header.options = options;
    this.header.windowSize = windowSize || this.defaultWindowSize;
  }
  build() {
    var rawHeader = [];
    var rawData = [];
    var rawVirtualHeader = [];
    rawHeader.push(this.header.srcPort >> 8, this.header.srcPort & 0xff);
    rawHeader.push(this.header.desPort >> 8, this.header.desPort & 0xff);
    rawHeader.push(parseInt((this.header.sequence >> 24) & 0xff), parseInt((this.header.sequence >> 16) & 0xff), parseInt((this.header.sequence >> 8) & 0xff), parseInt(this.header.sequence & 0xff));
    rawHeader.push(parseInt((this.header.ackNum >> 24) & 0xff), parseInt((this.header.ackNum >> 16) & 0xff), parseInt((this.header.ackNum >> 8) & 0xff), parseInt(this.header.ackNum & 0xff));
    // ヘッダ長4bitと予約3bitはとりあえず0埋め、コントロールと一緒にブッ込む
    if (Array.prototype.isPrototypeOf(this.header.control)) {
      var rawControl = 0;
      var control = this.header.control.map((i)=>i.toLowerCase());
      if (control.includes("ns")) {
        rawControl |= 0x0100;
        control = control.filter((i)=>i!="ns");
      }
      if (control.includes("cwr")) {
        rawControl |= 0x0080;
        control = control.filter((i)=>i!="cwr");
      }
      if (control.includes("ece")) {
        rawControl |= 0x0040;
        control = control.filter((i)=>i!="ece");
      }
      if (control.includes("urg")) {
        rawControl |= 0x0020;
        control = control.filter((i)=>i!="urg");
      }
      if (control.includes("ack")) {
        rawControl |= 0x0010;
        control = control.filter((i)=>i!="ack");
      }
      if (control.includes("psh")) {
        rawControl |= 0x0008;
        control = control.filter((i)=>i!="psh");
      }
      if (control.includes("rst")) {
        rawControl |= 0x0004;
        control = control.filter((i)=>i!="rst");
      }
      if (control.includes("syn")) {
        rawControl |= 0x0002;
        control = control.filter((i)=>i!="syn");
      }
      if (control.includes("fin")) {
        rawControl |= 0x0001;
        control = control.filter((i)=>i!="fin");
      }
      if (control.length > 0) {
        throw this.name + ": invalid control included"
      }
    } else {
      throw "invalid control type";
    }
    rawHeader.push(rawControl >> 8, rawControl & 0xff);
    rawHeader.push(this.header.windowSize >> 8, this.header.windowSize & 0xff);
    //チェックサム予約
    rawHeader.push(0x00, 0x00);
    //緊急ポインタ(?)
    rawHeader.push(0x00, 0x00);
    //options
    if (this.options != undefined) {
      rawHeader.push(...this.header.options.split(/(?<=^(?:(?:[0-9]|[a-f]|[A-F]){2}[:|-]?)+)[:|-]?/).map((i)=>{return parseInt(i, 16)}))
    }
    //パディング
    for (let i = 0; rawHeader.length % 4 > 0; i++) {
      rawHeader.push(0x00);
    }
    // data
    if (this.data == undefined || this.data == null) {
      ;
    } else if (NetworkFrame.prototype.isPrototypeOf(this.data)) {
      rawData.push(...(this.data.build()||[]));
    } else if (Uint8Array.prototype.isPrototypeOf(this.data)) {
      rawData.push(...this.data);
    } else if (Array.prototype.isPrototypeOf(this.data) && this.data.every((i)=>{return NetworkFrame.prototype.isPrototypeOf(i)||Uint8Array.prototype.isPrototypeOf(i)})) {
      for (let i of this.data) {
        if (NetworkFrame.prototype.isPrototypeOf(i)) {
          rawData.push(...(i.build()||[]));
        } else {
          rawData.push(...i);
        }
      }
    } else {
      throw "invalid data";
    }
    rawHeader.splice(12, 1, rawHeader[12] | ((rawHeader.length / 4) << 4));
    //virtual header
    if (!this.header.srcIP.split(".").map((i)=>parseInt(i)).every((i)=>0<=i&&i<=255)) {
      throw this.name + ": source IP address is wrong style";
    } else if (!this.header.desIP.split(".").map((i)=>parseInt(i)).every((i)=>0<=i&&i<=255)) {
      throw this.name + ": destination IP address is wrong style";
    } else {
      rawVirtualHeader.push(...this.header.srcIP.split(".").map((i)=>parseInt(i)));
      rawVirtualHeader.push(...this.header.desIP.split(".").map((i)=>parseInt(i)));
    }
    rawVirtualHeader.push(0x00, 0x06);
    rawVirtualHeader.push((rawHeader.length + rawData.length) >> 8, (rawHeader.length + rawData.length) & 0xff);
    // checksum
    var checksum = 0;
    var rawAll = [...rawVirtualHeader, ...rawHeader, ...rawData];
    for (let i = 0; i < rawAll.length; i += 2) {
      checksum += (rawAll[i] << 8) + (rawAll[i+1]||0);
    }
    checksum = ((checksum & 0xffff) + (checksum >> 16)) ^ 0xffff;
    rawHeader.splice(16, 2, checksum >> 8, checksum & 0xff);
    return new Uint8Array([...rawHeader, ...rawData]);
  }
  static fromBinary(binary) {
    binary = [...binary];
    //console.log(binary);
    var res = new this();
    res.header.srcPort = binary.slice(0, 2).reduce((i, i2)=>(i << 8)|i2, 0);
    res.header.desPort = binary.slice(2, 4).reduce((i, i2)=>(i << 8)|i2, 0);
    res.header.sequence = binary.slice(4, 8).reduce((i, i2)=>(i << 8)|i2, 0);
    res.header.ackNum = binary.slice(8, 12).reduce((i, i2)=>(i << 8)|i2, 0);
    res.header.control = [];
    if (binary[12] & 0x01) {
      res.header.control.push("NS");
    }
    if (binary[13] & 0x80) {
      res.header.control.push("CWR");
    }
    if (binary[13] & 0x40) {
      res.header.control.push("ECE");
    }
    if (binary[13] & 0x20) {
      res.header.control.push("URG");
    }
    if (binary[13] & 0x10) {
      res.header.control.push("ACK");
    }
    if (binary[13] & 0x08) {
      res.header.control.push("PSH");
    }
    if (binary[13] & 0x04) {
      res.header.control.push("RST");
    }
    if (binary[13] & 0x02) {
      res.header.control.push("SYN");
    }
    if (binary[13] & 0x01) {
      res.header.control.push("FIN");
    }
    res.header.windowSize = binary.slice(14, 16).reduce((i, i2)=>(i << 8)|i2, 0);
    res.header.options = binary.slice(20, (binary[12] >> 4)*4).reduce((a, b)=>a+b.toString(16).padStart(2, "0"), "");
    res.data = new Uint8Array(binary.slice((binary[12] >> 4)*4));
    return res;
  }
  name = "TCP";
  defaultWindowSize = 0xffff;
}

class UDPFrame extends NetworkFrame {
  constructor(srcIP, srcPort, desIP, desPort) {
    super();
    this.header.srcIP = srcIP;
    this.header.srcPort = srcPort;
    this.header.desIP = desIP;
    this.header.desPort = desPort;
  }
  build() {
    var rawHeader = [];
    var rawData = [];
    var rawVirtualHeader = [];
    rawHeader.push(this.header.srcPort >> 8, this.header.srcPort & 0xff);
    rawHeader.push(this.header.desPort >> 8, this.header.desPort & 0xff);
    rawHeader.push(0x00, 0x00); //セグメント長はあとで上書き
    rawHeader.push(0x00, 0x00); //チェックサムはあとで上書き
    // data
    if (this.data == undefined || this.data == null) {
      ;
    } else if (NetworkFrame.prototype.isPrototypeOf(this.data)) {
      rawData.push(...(this.data.build()||[]));
    } else if (Uint8Array.prototype.isPrototypeOf(this.data)) {
      rawData.push(...this.data);
    } else if (Array.prototype.isPrototypeOf(this.data) && this.data.every((i)=>{return NetworkFrame.prototype.isPrototypeOf(i)||Uint8Array.prototype.isPrototypeOf(i)})) {
      for (let i of this.data) {
        if (NetworkFrame.prototype.isPrototypeOf(i)) {
          rawData.push(...(i.build()||[]));
        } else {
          rawData.push(...i);
        }
      }
    } else {
      throw "invalid data";
    }
    rawHeader.splice(4, 2, (rawHeader.length+rawData.length) >> 8, (rawHeader.length+rawData.length) & 0xff)
    //virtual header
    if (!this.header.srcIP.split(".").map((i)=>parseInt(i)).every((i)=>0<=i&&i<=255)) {
      throw this.name + ": source IP address is wrong style";
    } else if (!this.header.desIP.split(".").map((i)=>parseInt(i)).every((i)=>0<=i&&i<=255)) {
      throw this.name + ": destination IP address is wrong style";
    } else {
      rawVirtualHeader.push(...this.header.srcIP.split(".").map((i)=>parseInt(i)));
      rawVirtualHeader.push(...this.header.desIP.split(".").map((i)=>parseInt(i)));
    }
    rawVirtualHeader.push(0x00, 0x11);
    rawVirtualHeader.push(...rawHeader.slice(4, 6));
    // checksum
    var checksum = 0;
    var rawAll = [...rawVirtualHeader, ...rawHeader, ...rawData];
    for (let i = 0; i < rawAll.length; i += 2) {
      checksum += (rawAll[i] << 8) + (rawAll[i+1]||0);
    }
    checksum = ((checksum & 0xffff) + (checksum >> 16)) ^ 0xffff;
    rawHeader.splice(6, 2, checksum >> 8, checksum & 0xff);
    return new Uint8Array([...rawHeader, ...rawData]);
  }
  static fromBinary(binary) {
    binary = [...binary];
    var res = new this();
    res.header.srcPort = binary.slice(0, 2).reduce((i, i2)=>(i << 8)|i2, 0);
    res.header.desPort = binary.slice(2, 4).reduce((i, i2)=>(i << 8)|i2, 0);
    /* try {
      if (res.header.desPort == 68) {
        res.data = DHCPFrame.fromBinary(binary.slice(8));
      } else if (res.header.srcPort == 53) {
        res.data = DNSFrame.fromBinary(binary.slice(8));
      } else {
        throw "";
      }
    } catch { */
    res.data = new Uint8Array(binary.slice(8));
    //}
    return res;
  }
  name = "UDP";
}

class DHCPFrame extends NetworkFrame {
  constructor(op, xid, secs, flags, srcIP, srcMAC, options) {
    super();
    this.header.op = op;
    this.header.xid = xid;
    this.header.secs = secs;
    this.header.flags = flags;
    this.header.yourIP = undefined;
    this.header.serverIP = undefined;
    this.header.srcIP = srcIP;
    this.header.srcMAC = srcMAC;
    this.header.options = options;
  }
  build() {
    var rawHeader = [];
    if ((typeof this.header.op == "number" && this.header.op == 0x0001) || (typeof this.header.op == "string" && this.header.op.toLowerCase() == "request")) {
      rawHeader.push(0x01);
    } else if ((typeof this.header.op == "number" && this.header.op == 0x0002) || (typeof this.header.op == "string" && this.header.op.toLowerCase() == "reply")) {
      rawHeader.push(0x02);
    } else {
      throw this.name + ": " + "unknown op";
    }
    rawHeader.push(0x01); //Ethernetは1
    rawHeader.push(0x06); //MACアドレスだから6
    rawHeader.push(0x00); //クライアントから一回も中継されていないから0
    rawHeader.push(this.header.xid >> 24, (this.header.xid >> 16) & 0xff, (this.header.xid >> 8) & 0xff, this.header.xid & 0xff);
    rawHeader.push(this.header.secs >> 8, this.header.secs & 0xff);
    if (Array.prototype.isPrototypeOf(this.header.flags)) {
      rawHeader.push(parseInt(this.header.flags.slice(0, 8).map((i)=>(i&1).toString()).join(""), 2));
      rawHeader.push(parseInt(this.header.flags.slice(8, 16).map((i)=>(i&1).toString()).join(""), 2));
    } else {
      rawHeader.push(this.header.flags >> 8, this.header.flags & 0xff);
    }
    if (!this.header.srcIP.split(".").map((i)=>parseInt(i)).every((i)=>0<=i&&i<=255)) {
      throw this.name + ": source IP address is wrong style";
    } else {
      rawHeader.push(...this.header.srcIP.split(".").map((i)=>parseInt(i)));
    }
    //yiaddr, 0埋め
    for (let i = 0; i < 4; i++) {
      rawHeader.push(0);
    }
    //siaddr 0埋め
    for (let i = 0; i < 4; i++) {
      rawHeader.push(0);
    }
    //giaddr 0埋め
    for (let i = 0; i < 4; i++) {
      rawHeader.push(0);
    }
    if (!this.header.srcMAC.match(/^(([0-9]|[a-f]|[A-F]){2}[:|-]?){6}(?<!:|-)$/)||false) {
      throw this.name + ": source MAC address is wrong style";
    } else {
      let l = this.header.srcMAC.split(/(?<=^(?:(?:[0-9]|[a-f]|[A-F]){2}[:|-]?)+)[:|-]?/).map((i)=>{return parseInt(i, 16)});
      for (let i = l.length; i < 16; i++) {
        l.push(0);
      }
      rawHeader.push(...l);
    }
    //Server Name, DHCPでは仕様にないため0埋め
    for (let i = 0; i < 64; i++) {
      rawHeader.push(0);
    }
    //Boot File Name, DHCPでは仕様にないため0埋め
    for (let i = 0; i < 128; i++) {
      rawHeader.push(0);
    }
    //options
    // フォーマット: [タグ(1byte)][先頭2byteを除くbyte数][データ]
    // 入力データ: {tagId: data, ...}
    rawHeader.push(0x63, 0x82, 0x53, 0x63); //Magic Cookie, DHCPとBootPの判別の為必須
    var rawOption = [];
    for (let i of [...(this.header.options.keys||Object.keys(this.header.options))]) {
      if (i == 53) { // DHCP Message Type
        rawOption.push(53, 1);
        if ((typeof this.header.options[i] == "number" && this.header.options[i] == 0x0001) || (typeof this.header.options[i] == "string" && this.header.options[i].toLowerCase() == "discover")) {
          rawOption.push(0x01);
        } else if ((typeof this.header.options[i] == "number" && this.header.options[i] == 0x0002) || (typeof this.header.options[i] == "string" && this.header.options[i].toLowerCase() == "offer")) {
          rawOption.push(0x02);
        } else if ((typeof this.header.options[i] == "number" && this.header.options[i] == 0x0003) || (typeof this.header.options[i] == "string" && this.header.options[i].toLowerCase() == "request")) {
          rawOption.push(0x03);
        } else if ((typeof this.header.options[i] == "number" && this.header.options[i] == 0x0004) || (typeof this.header.options[i] == "string" && this.header.options[i].toLowerCase() == "decline")) {
          rawOption.push(0x04);
        } else if ((typeof this.header.options[i] == "number" && this.header.options[i] == 0x0005) || (typeof this.header.options[i] == "string" && this.header.options[i].toLowerCase() == "ack")) {
          rawOption.push(0x05);
        } else {
          throw this.name + ": " + "unsupported DHCP message type";
        }
      } else {
        rawOption.push(i, this.header.options[i].length/2);
        rawOption.push(...this.header.options[i].split(/(?<=^(?:(?:[0-9]|[a-f]|[A-F]){2})+)[:|-]?/).map((i)=>{return parseInt(i, 16)}));
      }
    }
    rawOption.push(255);
    rawHeader.push(...rawOption);
    /* for (let i = 0; rawHeader.length < 314; i++) {
      rawHeader.push(0);
    }*/
    return new Uint8Array(rawHeader);
  }

  static fromBinary(binary) {
    binary = [...binary];
    var res = new this();
    res.header.op = binary[0];
    res.header.xid = binary.slice(4, 8).reduce((i, i2)=>(i << 8)|i2, 0);
    res.header.secs = binary.slice(8, 10).reduce((i, i2)=>(i << 8)|i2, 0);
    res.header.flags = binary.slice(10, 12).reduce((i, i2)=>(i << 8)|i2, 0);
    res.header.srcIP = binary.slice(12, 16).join(".");
    res.header.yourIP = binary.slice(16, 20).join(".");
    res.header.serverIP = binary.slice(20, 24).join(".");
    res.header.srcMAC = binary.slice(28, 34).map((i)=>i.toString(16).padStart(2, "0")).join(":");
    res.header.options = {};
    for (let i = 240; i < binary.length; i+=0) {
      if (binary[i] == 255) { break; }
      res.header.options[binary[i]] = binary.slice(i+2, i+binary[i+1]+2);
      i += binary[i+1]+2;
    }
    return res;
  }
  name = "DHCP";
}

class DNSFrame extends NetworkFrame {
  constructor(opcode, rd, questions) {
    super();
    this.header.id = Math.floor(Math.random()*65535);
    this.header.type = 0;
    this.header.opcode = opcode;
    this.header.rd = rd;
    this.header.questions = questions || [];
    this.header.answers = [];
  }
  build() {
    var rawHeader = [];
    rawHeader.push(this.header.id >> 8, this.header.id & 0xff);
    if ((typeof this.header.type == "number" && this.header.type == 0) || (typeof this.header.type == "string" && this.header.type.toLowerCase() == "request")) {
      rawHeader.push(0x00);
    } else if ((typeof this.header.type == "number" && this.header.type == 1) || (typeof this.header.type == "string" && this.header.type.toLowerCase() == "response")) {
      rawHeader.push(0x80);
    } else {
      throw this.name + ": invalid type";
    }
    if ((typeof this.header.opcode == "number" && this.header.opcode == 0) || (typeof this.header.opcode == "string" && this.header.opcode.toLowerCase() == "normal")) {
      rawHeader.push(rawHeader.pop() | 0x00);
    } else if ((typeof this.header.opcode == "number" && this.header.opcode == 4) || (typeof this.header.opcode == "string" && this.header.opcode.toLowerCase() == "notify")) {
      rawHeader.push(rawHeader.pop() | 0x20);
    } else if ((typeof this.header.opcode == "number" && this.header.opcode == 5) || (typeof this.header.opcode == "string" && this.header.opcode.toLowerCase() == "update")) {
      rawHeader.push(rawHeader.pop() | 0x28);
    } else {
      throw this.name + ": invalid opcode";
    }
    rawHeader.push(rawHeader.pop() | this.header.rd);
    rawHeader.push(0x00); //いまのところ未実装
    rawHeader.push(this.header.questions.length >> 8, this.header.questions.length & 0xff);
    rawHeader.push(this.header.answers.length >> 8, this.header.answers.length & 0xff);
    rawHeader.push(0x00, 0x00); //未実装
    rawHeader.push(0x00, 0x00); //未実装
    for (let i of this.header.questions) {
      for (let i2 of i[0].split(".")) {
        rawHeader.push(i2.length, ...i2.split("").map((i3)=>i3.charCodeAt(0)));
      }
      rawHeader.push(0x00);
      if (i[1] == "A") {
        rawHeader.push(0x00, 0x01);
      } else if (i[1] == "AAAA") {
        rawHeader.push(0x00, 0x1b);
      } else if (i[1] == "NS") {
        rawHeader.push(0x00, 0x02);
      } else {
        throw this.name + ": invalid question type";
      }
      if (i[2] == "IN") {
        rawHeader.push(0x00, 0x01);
      } else {
        throw this.name + ": invalid question class";
      }
    }
    for (let i of this.header.answers) {
      for (let i2 of i[0].split(".")) {
        rawHeader.push(i2.length, ...i2.split("").map((i3)=>i3.charCodeAt(0)));
      }
      rawHeader.push(0x00);
      if (i[1] == "A") {
        rawHeader.push(0x00, 0x01);
      }
      if (i[2] == "IN") {
        rawHeader.push(0x00, 0x01);
      }
      rawHeader.push(i[3] >> 24, (i[3] >> 16) & 0xff, (i[3] >> 8) & 0xff, i[3] & 0xff);
      rawHeader.push(i[4].length >> 8, i[4].length & 0xff);
      rawHeader.push(...i[4]);
    }
    return new Uint8Array(rawHeader);
  }
  static fromBinary(binary) {
    binary = [...binary];
    var res = new this();
    res.header.id = binary.slice(0, 2).reduce((i, i2)=>(i << 8)|i2, 0);
    res.header.opcode = binary[2] >> 7;
    res.header.type = (binary[2] >> 3) & 0x0f;
    res.header.rd = binary[2] & 0x01;
    var index = 12;
    for (let i = 0; i < binary.slice(4, 6).reduce((i, i2)=>(i << 8)|i2, 0); i++) {
      var question = [""];
      while (true) {
        if (index > binary.length) {
          throw this.name + ": something wrong! It's going to loop endlessly! escaped.";
        }
        for (let i2 = 0; i2 < binary[index]; i2++) {
          question[0] += String.fromCharCode(binary[index+i2+1]);
        }
        index += binary[index] + 1;
        if (binary[index] == 0) {
          index += 1;
          break;
        } else {
          question[0] += ".";
        }
      }
      var qtype = binary.slice(index, index+2).reduce((i, i2)=>(i << 8)|i2, 0);
      if (qtype == 0x01) {
        question.push("A");
      } else if (qtype == 0x1b) {
        question.push("AAAA");
      } else if (qtype == 0x02) {
        question.push("NS");
      } else {
        question.push(qtype);
      }
      index += 2;
      var qclass = binary.slice(index, index+2).reduce((i, i2)=>(i << 8)|i2, 0);
      if (qclass == 0x01) {
        question.push("IN");
      } else {
        question.push(qclass);
      }
      index += 2;
      res.header.questions.push(question);
    }
    for (let i = 0; i < binary.slice(6, 8).reduce((i, i2)=>(i << 8)|i2, 0); i++) {
      var answer = [""];
      if (binary[index] >> 6 == 0x03) {
        var index2 = binary[index+1];
        while (true) {
          if (index2 > binary.length) {
            throw this.name + ": something wrong! It's going to loop endlessly! escaped.";
          }
          for (let i2 = 0; i2 < binary[index2]; i2++) {
            answer[0] += String.fromCharCode(binary[index2+i2+1]);
          }
          index2 += binary[index2] + 1;
          if (binary[index2] == 0) {
            index += 2;
            break;
          } else {
            answer[0] += ".";
          }
        }
      } else {
        while (true) {
          if (index > binary.length) {
            throw this.name + ": something wrong! It's going to loop endlessly! escaped.";
          }
          for (let i2 = 0; i2 < binary[index]; i2++) {
            answer[0] += String.fromCharCode(binary[index+i2+1]);
            //console.log(answer[0]);
          }
          index += binary[index] + 1;
          if (binary[index] == 0) {
            index += 1;
            break;
          } else {
            answer[0] += ".";
          }
        }
      }
      var atype = binary.slice(index, index+2).reduce((i, i2)=>(i << 8)|i2, 0);
      if (atype == 0x01) {
        answer.push("A");
      } else if (atype == 0x1b) {
        answer.push("AAAA");
      } else if (atype == 0x02) {
        answer.push("NS");
      } else {
        answer.push(atype);
      }
      index += 2;
      var aclass = binary.slice(index, index+2).reduce((i, i2)=>(i << 8)|i2, 0);
      if (aclass == 0x01) {
        answer.push("IN");
      } else {
        answer.push(aclass);
      }
      index += 2;
      answer.push(binary.slice(index, index+4).reduce((i, i2)=>(i << 8)|i2, 0));
      index += 4;
      answer.push(binary.slice(index+2, index+binary.slice(index, index+2).reduce((i, i2)=>(i << 8)|i2, 0)+2));
      index += binary.slice(index, index+2).reduce((i, i2)=>(i << 8)|i2, 0)+2;
      res.header.answers.push(answer);
    }
    return res;
  }
  name = "DNS";
}


class TLSFrame extends NetworkFrame {
  constructor() {
    super();
    this.header.version = this.prototype.getVersionBinary();
    this.header.childType = undefined;
    this.encrypted = false;
  }
  static fromBinary(binary, encrypted=false) {
    var res = new this();
    let childType = res.header.childType = binary[0];
    res.header.version = (binary[1] << 8) + binary[2];
    res.encrypted = encrypted;
    /*if (binary.length != ((binary[3] << 8) + binary[4]) - 5) {
      throw "payload length is wrong";
    }*/
    if (!encrypted) {
      if (childType == 20) {
        res.body = TLSChangeCipherFrame.fromBinary(binary.slice(5));
      } else if (childType == 21) {
        res.body = TLSAlertFrame.fromBinary(binary.slice(5));
      } else if (childType == 22) {
        res.body = TLSHandshakeFrame.fromBinary(binary.slice(5));
      } else if (childType == 23) {
        res.body = TLSAppDataFrame.fromBinary(binary.slice(5));
      }
    }
    return res;
  }
  static getVersionBinary() {
    if (this.version == "1.0") {
      return 0x0301;
    } else if (this.version == "1.1") {
      return 0x0302;
    } else if (this.version == "1.2") {
      return 0x0303;
    } else if (this.version == "1.3") {
      return 0x0304;
    }
  }
  name = "TLS";
  version = "1.2";
}

class TLSCipherSuits {
  static TLS_NULL_WITH_NULL_NULL = [0, 0]; //[this.NULL, this.NULL];

  static TLS_RSA_WITH_AES_128_CBC_SHA = [0x00, 0x2f];

  static TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = [0xC0, 0x13];
  static TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = [0xC0, 0x14];
  static TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = [0xC0, 0x2F];
  static TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA284 = [0xC0, 0x2F];
  
  static KeyExchangeAlgorithms = {
    NULL:0,
    RSA:1,
    RSA_PSK:2,
    DH_RSA:3,
    DHE_RSA:4,
    ECDH_RSA:5,
    ECDHE_RSA:6,
    DH_DSS:7,
    DHE_DSS:8,
    ECDH_ECDSA:9,
    ECDHE_ECDSA:10,
    DH_ANON:11,
    ECDH_ANON:12
  };
  static HashAlgorithms = {
    NONE:0,
    MD5:1,
    SHA1:2,
    SHA224:3,
    SHA256:4,
    SHA384:5,
    SHA512:6
  };
  static SignatureAlgorithms = {
    ANONYMOUS:0,
    RSA:1,
    DSA:2,
    ECDSA:3
  };
  static Ciphers = {
    NULL: 0,
    RC4_128: 1,
    "3DES_EDE_CBC": 2,
    AES_128_CBC: 3,
    AES_256_CBC: 4
  };
  static MACs = {
    NULL: 0,
    MD5: 0
  };
}

class TLSHandshakeFrame extends NetworkFrame {
  constructor(type, options, extensions) {
    super();
    this.type = type;
    if (type == 1) {
      this.random = crypto.getRandomValues(new Uint8Array(32));
      res.session = options.session || 0;
    }
  }
  static fromBinary(binary, options={}) {
    var res = new this();
    binary = [...binary];
    res.type = binary[0];
    res.length = binary.slice(1, 4).reduce((i, i2)=>(i << 8)|i2, 0);
    if (res.type == 1 || res.type == 2) {
      let version = binary.slice(4, 6).reduce((i, i2)=>(i << 8)|i2, 0);
      /*if (res.tlsVersion != version) {
        throw "A TLS Handshake Frame has two different versions!";
      }*/
      res.random = binary.slice(6, 38);
      res.session = binary[38];
      let i = 39;
      if (res.type == 1) {
        res.availableChangeCiphers = [];
        for (let i2 = 0; i2 < binary.slice(i, i+2).reduce((i, i2)=>(i << 8)|i2, 0); i2 += 2) {
          res.availableChangeCiphers.push(binary.slice(i+i2+2, i+i2+4).reduce((i, i2)=>(i << 8)|i2, 0));
        }
        i += binary.slice(i, i+2).reduce((i, i2)=>(i << 8)|i2, 0) + 2;
        res.availableCompressions = [];
        for (let i2 = 0; i2 < binary[i]; i2++) {
          res.availableCompressions.push(binary[i+i2+1]);
        }
        i += binary[i] + 1;
      } else {
        res.changeCipher = binary.slice(i, i+2).reduce((i, i2)=>(i << 8)|i2, 0);
        i += 2;
        res.compression = binary[i];
        i += 1;
      }
      res.extensions = [];
      let extensionsLength = binary.slice(i, i+2).reduce((i, i2)=>(i << 8)|i2, 0);
      i += 2;
      let i2 = 0;
      while (i2 < extensionsLength) {
        res.extensions.push({
          type: binary.slice(i+i2, i+i2+2).reduce((i, i2)=>(i << 8)|i2, 0),
          length: binary.slice(i+i2+2, i+i2+4).reduce((i, i2)=>(i << 8)|i2, 0)
        });
        i2 += 4;
        res.extensions.at(-1).data = binary.slice(i+i2, i+i2+res.extensions.at(-1).length);
        i2 += res.extensions.at(-1).length;
      }
    } else if (res.type == 11) {
      let i = 4;
      let length = binary.slice(i, i+3).reduce((i, i2)=>(i << 8)|i2, 0)
      i += 3;
      if (binary.length - i != length) {
        throw "certificates length is wrong";
      }
      let i2 = 0;
      res.certificates = [];
      while (i2 < length) {
        let certBinary = binary.slice(i+i2+3, i+i2+3+binary.slice(i+i2, i+i2+3).reduce((i, i2)=>(i << 8)|i2, 0));
        i2 += 3 + binary.slice(i+i2, i+i2+3).reduce((i, i2)=>(i << 8)|i2, 0);
        res.certificates.push(Certificate.fromBinary(certBinary));
      }
    } else if (type == 12)  {
      /* struct {
          select (KeyExchangeAlgorithm) {
              case dh_anon:
                  ServerDHParams params;
              case dhe_dss:
              case dhe_rsa:
                  ServerDHParams params;
                  digitally-signed struct {
                      opaque client_random[32];
                      opaque server_random[32];
                      ServerDHParams params;
                  } signed_params;
              case rsa:
              case dh_dss:
              case dh_rsa:
                  struct {} ;
                 /* message is omitted for rsa, dh_dss, and dh_rsa 
              /* may be extended, e.g., for ECDH -- see [TLSECC] 
              case ec_diffie_hellman:
                  ServerECDHParams    params;
                  Signature           signed_params;
          };
      } ServerKeyExchange; */
      /* struct {
            ECParameters    curve_params;
            ECPoint         public;
        } ServerECDHParams; */
      /* struct {
            ECCurveType    curve_type;
            select (curve_type) {
                case explicit_prime:
                    opaque      prime_p <1..2^8-1>;
                    ECCurve     curve;
                    ECPoint     base;
                    opaque      order <1..2^8-1>;
                    opaque      cofactor <1..2^8-1>;
                case explicit_char2:
                    uint16      m;
                    ECBasisType basis;
                    select (basis) {
                        case ec_trinomial:
                            opaque  k <1..2^8-1>;
                        case ec_pentanomial:
                            opaque  k1 <1..2^8-1>;
                            opaque  k2 <1..2^8-1>;
                            opaque  k3 <1..2^8-1>;
                    };
                    ECCurve     curve;
                    ECPoint     base;
                    opaque      order <1..2^8-1>;
                    opaque      cofactor <1..2^8-1>;
                case named_curve:
                    NamedCurve namedcurve;
            };
        } ECParameters; */
      /* struct {
            opaque a <1..2^8-1>;
            opaque b <1..2^8-1>;
        } ECCurve; */
      /* struct {
            opaque point <1..2^8-1>;
        } ECPoint; */
      // enum { ec_basis_trinomial, ec_basis_pentanomial } ECBasisType;
      /* enum { ecdsa } SignatureAlgorithm;

          select (SignatureAlgorithm) {
              case ecdsa:
                  digitally-signed struct {
                      opaque sha_hash[sha_size];
                  };
          } Signature; 
      ServerKeyExchange.signed_params.sha_hash
        SHA(ClientHello.random + ServerHello.random +
                                          ServerKeyExchange.params); */
      /* enum { dhe_dss, dhe_rsa, dh_anon, rsa, dh_dss, dh_rsa
            /* may be extended, e.g., for ECDH -- see [TLSECC] 
           } KeyExchangeAlgorithm;
        
      struct {
          opaque dh_p<1..2^16-1>;
          opaque dh_g<1..2^16-1>;
          opaque dh_Ys<1..2^16-1>;
      } ServerDHParams;     /* Ephemeral DH parameters */
      let i = 4;
    } else if (type == 16) {
      let i = 4;
      if (binary.length - 1 != binary[i]) {
        throw "Client key exchange includes wrong length info for the key";
      }
      res.publicKey = binary.slice(i+1, i+1+binary[i]);
    } else if (type == 15) {
      ;
    }
    return res;
  }
  name = "TLSHandshake";
}

class TLSChangeCipherFrame extends NetworkFrame {
  constructor() {
    super();
  }
  name = "TLSChangeCipher";
}

class TLSAppDataFrame extends TLSFrame {
  constructor() {
    super();
  }
  name = "TLSAppData";
}

class TLSAlertFrame extends TLSFrame {
  constructor() {
    super();
  }
  static fromBinary(binary) {}
  name = "TLSAlert";
}


class HTTPRequestFrame extends NetworkFrame {
  constructor(uri, options) {
    super();
    this.uri = uri;
    this.options = options || {};
  }
  build() {
    var uri = new URL(this.uri);
    if (Object.prototype.isPrototypeOf(this.options)) {
      var options = Object.fromEntries([...Object.entries(this.options)]);
    } else if (Map.prototype.isPrototypeOf(this.opitons)) {
      var options = Object.fromEntries(this.options.entries());
    } else {
      throw this.name + ": invalid options type";
    }
    if (options.method == undefined) {
      options.method = "GET";
    } else if (typeof options.method != "string") {
      throw this.name + ": invalid method type"
    } else if (["GET", "POST", "HEAD", "OPTIONS"].includes(this.options.method.toUpperCase())) {
      options.method = options.method.toUpperCase();
    } else {
      throw this.name + ": unsupported method";
    }
    //console.log(this);
    var requestRow = `${options.method} ${uri.pathname} HTTP/${this.version}`;
    var headers = [];
    headers.push(["Host", uri.host]);
    headers.push(["Accept", options["Accept"] || "*/*"]);
    var headerRow = headers.map((i)=>{return `${i[0]}: ${i[1]}`}).join("\r\n")
    var rawHeader = new Uint8Array([...requestRow.split(""), "\r", "\n", ...headerRow.split(""), "\r", "\n", "\r", "\n"].map((i)=>{return i.charCodeAt(0) & 0xff}))
    return rawHeader;
  }
  static fromBinary(binary) {
    var text = (new TextDecoder()).decode(binary);
    var res = new this();
    var requestRowMatch = text.match(/^(?<method>GET|POST|HEAD|OPTIONS) (?<path>.+?) HTTP\/(?<version>1|1\.1|2|3)(?=\n)/);
    var headerRowMatch = [...text.matchAll(/(?<key>.*?) ?: ?(?<value>.*?)(?:\n|$)/g)];
    var headers = new Map(headerRowMatch.map((i)=>[i.groups.key, i.groups.value]));
    headers.method = requestRowMatch.groups.method;
    res.uri = new URL(requestRowMatch.groups.path, `http://${headers.get("Host")}`);
    headers.delete("Host");
    res.options = Object.fromEntries([...headers.entries()]);
    //console.log([res, requestRowMatch, headers]);
    return res;
  }
  name = "HTTPRequest";
  version = "1.1";
}

class HTTPResponseFrame extends NetworkFrame {
  constructor(status, options) {
    super();
    this.status = status;
    this.options = options;
    this.description = "";
  }
  build() {
    if (Object.prototype.isPrototypeOf(this.options)) {
      var options = Object.fromEntries([...Object.entries(this.options)]);
    } else if (Map.prototype.isPrototypeOf(this.opitons)) {
      var options = Object.fromEntries(this.options.entries());
    } else {
      throw this.name + ": invalid options type";
    }
    //console.log(this);
    var requestRow = `HTTP/${this.version} ${this.status} ${this.description}`;
    var headers = [];
    var headerRow = headers.map((i)=>{return `${i[0]}: ${i[1]}`}).join("\n");
    var rawHeader = new Uint8Array([...requestRow.split(""), "\n", ...headerRow.split("")].map((i)=>{return i.charCodeAt(0) & 0xff}))
    return rawHeader;
  }
  static fromBinary(binary) {
    var binary = binary;
    var text = (new TextDecoder()).decode(binary);
    var data = [];
    for (let i = 0; i < binary.length; i++) {
      if ([...binary.slice(i, i+4)].every((i, index)=>i==[13, 10, 13, 10][index])) {
        text = (new TextDecoder()).decode(binary.slice(0, i));
        data = binary.slice(i+4);
        break;
      }
    }
    console.log(text);
    var res = new this();
    var responseRowMatch = text.match(/^HTTP\/(?<version>1|1\.1|2|3) (?<status>\d*) (?<description>.*?)(?=\r\n)/);
    var headerRowMatch = [...text.matchAll(/(?<key>.*?) ?: ?(?<value>.*?)(?:\r\n|$)/g)];
    var headers = new Map(headerRowMatch.map((i)=>[i.groups.key, i.groups.value]));
    res.status = parseInt(responseRowMatch.groups.status)
    res.options = Object.fromEntries([...headers.entries()]);
    //console.log([res, responseRowMatch, headers]);
    res.options.payload = data;
    return res;
  }
  name = "HTTPResponse";
  version = "1.1";
}


class WebSockProxy extends EventTarget {
  constructor(url, reconnect=true, autoconnect=true) {
    super();
    this.url = url;
    this.ws = undefined;
    this.reconnect = reconnect
    this.queue = [];
    this.connecting = false;
    this.exiting = false;
    if (autoconnect) {
      this.connect();
    }
  }
  connect() {
    if (this.connecting) {
      return;
    }
    this.connecting = true;
    this.exiting = false;
    try {
      this.ws = new WebSocket(this.url);
    } catch {
      setTimeout(this.connect, 1000);
      return;
    }
    this.ws.addEventListener("open", (e)=>{
      if (network.IP != undefined && network.MAC != undefined) {
        var HelloWorld = new EthernetFrame(network.MAC, network.MAC, "arp");
        HelloWorld.data = new ARPFrame(1, "ipv4", 6, 4, 1, network.MAC, network.IP, network.MAC, network.IP);
        //console.log(HelloWorld)
        this.ws.send(HelloWorld.build());
      }
      this.connecting = false;
      for (let i = this.queue.shift(); this.queue.length > 0; i = this.queue.shift()) {
        this.ws.send(i);
      }
    });
    this.ws.addEventListener("open", async (e)=>{
      setTimeout(()=>{this.dispatchEvent(e);}, 0)
    });
    this.ws.addEventListener("message", async (e)=>{
      var date = Date.now();
      if(!this.connecting) {
        e.data.arrayBuffer().then((buffer)=>{
          var ev = new MessageEvent("message", {data:EthernetFrame.fromBinary(new Uint8Array(buffer))});
          if (ev.data.header.desMAC == network.MAC || ev.data.header.desMAC.toLowerCase() == "ff:ff:ff:ff:ff:ff") {
            setTimeout(()=>{this.dispatchEvent(ev);}, 0);
            console.debug(`raw -> transport : ${Date.now()-date} ms`);
          }
        });
      }
    });
    this.ws.addEventListener("error", async (e)=>{
      this.connecting = false;
      setTimeout(this.connect, 10);
    });
    this.ws.addEventListener("close", async (e)=>{
      if (this.reconnect && !this.exiting) {
        setTimeout(this.connect, 10);
      } else {
        setTimeout(()=>{this.dispatchEvent(e);}, 0)
      }
    });
  }
  send(data) {
    if (this.ws.readyState != 1) {
      this.queue.push(data);
    } else {
      this.ws.send(data);
      console.debug("send data "+data.length+"bytes");
    }
  }
  close() {
    this.exiting = true;
    this.ws.close();
  }
}

class NetworkSocketManager {
  constructor(ws, hosts, arps) {
    this.TCPPorts = new Map();
    this.UDPPorts = new Map();
    this.hosts = hosts || new Hosts();
    this.arps = arps || new ARPTable();
    this.ws = ws;
    this.ws.addEventListener("message", async (e)=>{await this.handleMessage(e);});
  }
  getTCPSocket(srcPort, desPort, desIP) {
    if (this.TCPPorts.has(srcPort)) {
      throw "Requested port is already used";
    }
    this.TCPPorts.set(srcPort, true);
    var sock = new TCPSocket(this, srcPort, desPort, desIP);
    this.TCPPorts.set(srcPort, sock);
    return sock;
  }
  getUDPSocket(srcPort, desPort, desIP) {
    if (this.UDPPorts.has(srcPort)) {
      throw "Requested port is already used";
    }
    this.UDPPorts.set(srcPort, true);
    var sock = new UDPSocket(this, srcPort, desPort, desIP);
    this.UDPPorts.set(srcPort, sock);
    return sock;
  }
  async handleMessage(e) {
    var data = e.data;
    if (data.header.protocol == protocols.ARP) {
      //console.log([data, ARPFrame.fromBinary(data.data)]);
      if (data.header.desMAC != network.MAC || ARPFrame.fromBinary(data.data).header.opcode != 1) { return; }
      data.data = ARPFrame.fromBinary(data.data);
      if (data.data.header.desMAC == network.MAC || data.data.header.desIP == network.IP) {
        var a = EthernetFrame.fromBinary(data.build());
        a.data = ARPFrame.fromBinary(a.data);
        a.header.desMAC = a.header.srcMAC;
        a.header.srcMAC = network.MAC;
        a.data.header.opcode = 2;
        a.data.header.srcMAC = network.MAC;
        a.data.header.srcIP = network.IP;
        a.data.header.desMAC = data.data.header.srcMAC;
        a.data.header.desIP = data.data.header.srcIP;
        this.ws.send(a.build());
      }
      return;
    } else if (data.header.protocol != protocols.IPv4) { return; }
    data.data = IPFrame.fromBinary(data.data);
    //console.log(data);
    if (data.data.header.protocol == protocols.TCP) {
      data.data.data = TCPFrame.fromBinary(data.data.data);
      if (this.TCPPorts.has(data.data.data.header.desPort)) {
        console.debug(["tcp", data.data.data]);
        this.TCPPorts.get(data.data.data.header.desPort).dispatchEvent(new MessageEvent("message", {data:data.data.data}));
      }
    }
    if (data.data.header.protocol == protocols.UDP) {
      data.data.data = UDPFrame.fromBinary(data.data.data);
      if (this.UDPPorts.has(data.data.data.header.desPort)) {
        console.debug(["udp", data.data.data]);
        this.UDPPorts.get(data.data.data.header.desPort).dispatchEvent(new MessageEvent("message", {data:data.data.data}));
      }
    }
  }
  async doARP(ipaddr) {
    var a = new EthernetFrame("ff:ff:ff:ff:ff:ff", network.MAC, "arp");
    var b = a.data = new ARPFrame("ipv4", 6, 4, "request", network.MAC, network.IP, "00:00:00:00:00:00", ipaddr);
    for (let i = 0; i < 3; i++) {
      var res;
      try {
        setTimeout(()=>{this.ws.send(a.build());}, 10);
        //console.log(ipaddr);
        res = (await waitUntil(this.ws, "message", 3000, {filter:(e)=>e.data.header.desMAC == network.MAC && e.data.header.protocol == protocols.ARP && ARPFrame.fromBinary(e.data.data).header.srcIP == ipaddr})).data;
        //console.log(res);
        res = ARPFrame.fromBinary(res.data);
      } catch (e) {
        console.error(e);
        continue;
      }
      //console.log(res);
      this.arps.setHost(ipaddr, res.header.srcMAC);
      return res.header.srcMAC;
    }
    throw "Host unreachable";
  }
  async send(sock, data) {
    var protocol;
    if (TCPSocket.prototype.isPrototypeOf(sock)) {
      if (this.TCPPorts.has(sock.srcPort) && this.TCPPorts.get(sock.srcPort) == sock) {
        protocol = 6;
      } else {
        throw "tcp socket not registered";
      }
    } else if (UDPSocket.prototype.isPrototypeOf(sock)) {
      if (this.UDPPorts.has(sock.srcPort) && this.UDPPorts.get(sock.srcPort) == sock) {
        protocol = 17;
      } else {
        throw "udp socket not registered";
      }
    } else {
      throw "unknown socket type";
    }
    if (network.IP == "0.0.0.0" || network.gateway == undefined) {
      var desMAC = "ff:ff:ff:ff:ff:ff"; 
    } else if (network.IP.split(".").reduce((i, i2)=>{return (i<<8)|parseInt(i2)})&network.subnet.split(".").reduce((i, i2)=>{return (i<<8)|parseInt(i2)}) == sock.desIP.split(".").reduce((i, i2)=>{return (i<<8)|parseInt(i2)})) {
      var desMAC = this.arps.getHost(sock.desIP);
      if (desMAC == undefined) {
        desMAC = await this.doARP(sock.desIP);
      }
    } else {
      var desMAC = network.gateway.MAC;
      if (this.arps.getHost(sock.desIP) == undefined) {
        this.arps.setHost(sock.desIP, network.gateway.MAC);
      }
    }
    var a = new EthernetFrame(desMAC, network.MAC, "ipv4");
    var b = a.data = new IPFrame(4, 0, 0, 0, 0, 0x80, protocol, network.IP, sock.desIP);
    b.data = data;
    //console.log(a);
    console.log(["send", a]);
    this.ws.send(a.build());
  }
}

class NetworkSocket extends EventTarget {
  constructor() {
    super();
  }
}
class TCPSocket extends NetworkSocket {
  #manager;
  #srcPort;
  #desPort;
  #desIP;
  #promise
  #resolve;
  #reject;
  constructor(manager, srcPort, desPort, desIP) {
    super();
    this.#manager = manager;
    this.#srcPort = srcPort;
    this.#desPort = desPort;
    this.#desIP = desIP;
    this.buffer = new CustomBuffer();
    this.bufferSize = 0;
    this.queue = [];
    this.dataSize = -1;
    this.windowSize = 0;
    this.recieved = 0;
    this.closed = false;
    this.ackId;
    this.#promise = new Promise((resolve, reject)=>{this.#resolve = resolve; this.#reject = reject;});
  }
  get srcPort() { return this.#srcPort; }
  get desPort() { return this.#desPort; }
  get desIP() { return this.#desIP; }
  async send(data) {
    var tcp = new TCPFrame(network.IP, this.#srcPort, this.#desIP, this.#desPort, this.sequence, this.ackNum, ["ACK","PSH"], this.windowSize);
    tcp.data = data;
    await this.#manager.send(this, tcp);
  }
  async *listen(parser) {
    if (parser == undefined) {
      parser = (e)=>e;
    }
    this.parser = parser;
    if (this.#promise == undefined) {
      this.#promise = new Promise((resolve, reject)=>{this.#resolve = resolve; this.#reject = reject;});
    }
    while (!this.closed) {
      yield await this.#promise;
    }
  }
  async get(parser) {
    if (parser == undefined) {
      parser = (e)=>e;
    }
    this.parser = parser;
    if (this.queue.length > 0) {
      return this.queue.shift();
    } else {
      return await this.#promise;
    }
  }
  async handshake() {
    this.ackNum = 0;
    this.sequence = Math.floor(Math.random()*4096);
    this.sequences = {};
    var packet = new TCPFrame(network.IP, this.#srcPort, this.#desIP, this.#desPort, this.sequence, this.ackNum, ["SYN",], "0402");
    this.windowSize = packet.header.windowSize;
    await this.#manager.send(this, packet);
    var res = (await waitUntil(this, "message", 10000, {filter:(e)=>e.data.header.control.includes("ACK")})).data;
    this.sequence = res.header.ackNum;
    this.ackNum = res.header.sequence + 1;
    this.desSequence = this.ackNum;
    this.windowSize = Math.min(this.windowSize, res.header.windowSize);
    if (res.header.control.includes("SYN")) {
      await this.#manager.send(this, new TCPFrame(network.IP, this.#srcPort, this.#desIP, this.#desPort, this.sequence, this.ackNum, ["ACK",]));
    }
    console.log("handshaked");
    this.addEventListener("message", this.handleMessage)
    //this.interval = setInterval(async ()=>{await this.tellMissed();}, 1000);
  }
  async close() {
    try {
      clearInterval(this.ackId);
    } catch {}
    await this.#manager.send(this, new TCPFrame(network.IP, this.#srcPort, this.#desIP, this.#desPort, this.sequence, this.ackNum, ["FIN"]));
    var res = (await waitUntil(this, "message", 10000, {filter:(e)=>e.data.header.control.includes("ACK")})).data;
    this.closed = true;
    this.#resolve = undefined;
    this.dispatchEvent(new Event("close"));
  }
  async tellMissed() {
    var missed = this.getMissed();
    if (missed != this.ackNum && missed != this.desSequence + this.dataSize) {
      await this.#manager.send(this, new TCPFrame(network.IP, this.#srcPort, this.#desIP, this.#desPort, this.sequence, missed, ["ACK",]));
    }
  }
  getMissed() {
    var index = this.buffer.indexOf(null);
    if (index != -1) {
      return index;
    } else {
      return this.buffer.length;
    }
  }
  async handleMessage(e) {
    if (this.ackId != undefined) {clearInterval(this.ackId); this.ackId = undefined;}
    var data = e.data;
    var missed = this.getMissed();
    this.sequences[data.header.sequence] = data.data.length;
    console.log(`seq ${data.header.sequence}  ackNum ${data.header.ackNum}:  ${data.header.control.join(" ")}     ${data.data.length}   <---`);
    if (true) { //this.buffer.slice(data.header.sequence-this.desSequence, data.header.sequence-this.desSequence+data.data.length).includes(null) || this.buffer.length <= data.header.sequence-this.desSequence) {
      this.buffer.set(data.header.sequence-this.desSequence, data.data);
      this.dispatchEvent(new ProgressEvent("progress", {"total": this.dataSize, "loaded": this.buffer.reduce((a, b)=>a+(b!=null), 0), "lengthComputable":(this.dataSize > 0)}));
    }
    console.log(this.buffer.length);
    this.recieved += 1;
    if (this.buffer.slice(data.header.sequence-this.desSequence, data.header.sequence-this.desSequence+data.data.length).includes(null) || this.buffer.slice(data.header.sequence-this.desSequence, data.header.sequence-this.desSequence+data.data.length).length == 0) { // || this.getMissed() > data.header.sequence) { return; }
      //this.buffer.set(data.header.sequence-this.desSequence, data.data);
      console.log(this.buffer.length);
      console.log(this.bufferSize);
    }
    this.sequence = data.header.ackNum;
    this.ackNum = (data.header.sequence + data.data.length) & 0xffffffff;
    if (data.header.control.includes("PSH")) {
      this.dataSize = data.header.sequence + data.data.length - this.desSequence;
    }
    if (this.buffer.length!=0 && !this.buffer.includes(null) && this.dataSize != -1) {
      console.log(this.buffer);
      var res = new Uint8Array([...this.buffer]); //.sort((a, b)=>a[0]-b[0]).map((i)=>i[1][1].data).reduce((a, b)=>[...a, ...b]));
      //this.buffer.clear();
      console.log(res);
      console.log(`recieved ${this.recieved} packets`);
      if (this.#promise != undefined) {
        if (this.parser != undefined) {
          res.data = this.parser(res.data);
        }
        var ev = new MessageEvent("recieve", {data:res});
        this.dispatchEvent(ev);
        this.#resolve(res);
        this.buffer.clear();
        this.desSequence += this.dataSize;
        this.#promise = new Promise((resolve, reject)=>{this.#resolve = resolve; this.#reject = reject;});
      } else {
        this.queue.push(res);
      }
    }
    let ranges = [];
    for (let i of Object.keys(this.sequences).map((i)=>parseInt(i)>>>0).sort()) {
      if (ranges.length > 0) {
        if (ranges.at(-1)[0] >= ranges[0][0] + this.windowSize) {
          ranges.pop(-1);
          break;
        } else if (ranges.at(-1)[1] >= ranges[0][0] + this.windowSize) {
          ranges.at(-1)[1] = ranges[0][0] + this.windowSize;
          break;
        }
      }
      if (ranges.length == 0 || ranges.at(-1)[1] < i) {
        ranges.push([i, i+this.sequences[i]]);
      } else {
        ranges.at(-1)[1] = i+this.sequences[i];
      }
    }
    console.log(ranges)
    if (data.data.length == 0) {
      ;
    } else if (true) { //ranges.length >=0 &&( (true && ranges.at(-1)[1] + this.desSequence + 1 <= data.header.sequence + data.data.length) || this.getMissed()+this.desSequence >= data.header.sequence + data.data.length)) { //data.data.length != 0) { // && missed >= data.header.sequence) { // data.header.control.includes("PSH") || this.recieved < 100 && 
      console.log(`--->   seq ${this.sequence}  ackNum ${this.getMissed()+this.desSequence} / ${ranges[0][1]+this.sequences[ranges[0][1]]}:  ${["ACK",].join(" ")}     ${0}`);
      console.log([ranges,  this.buffer.includes(null)?("05"+(ranges.length*8+2).toString(16).padStart(2, "0")+ranges.reduce((a, b)=>a+b[0].toString(16).padStart(8, "0")+b[1].toString(16).padStart(8, "0"), "")):undefined])
      this.ackId = setTimeout(async (options)=>{
        await this.#manager.send(this, new TCPFrame(network.IP, this.#srcPort, this.#desIP, this.#desPort, this.sequence, this.desSequence+this.getMissed(), ["ACK",], options));
      }, 200, this.buffer.includes(null)&&(ranges.length > 1)?("05"+(((ranges.length>5?40:ranges.length*8)+2)>>>0).toString(16).padStart(2, "0")+ranges.slice(-5).reduce((a, b)=>a+((((b[0]+this.desSequence)>>>0)&0xffffffff)>>>0).toString(16).padStart(8, "0")+(((b[1]+this.desSequence)&0xffffffff)>>>0).toString(16).padStart(8, "0"), "")):undefined);
    }
    if (data.header.control.includes("FIN")) {
      this.ackNum += 1;
      await this.#manager.send(this, new TCPFrame(network.IP, this.#srcPort, this.#desIP, this.#desPort, this.sequence, this.ackNum, ["ACK"]));
      await this.close();
      if (this.buffer.length!=0 && !this.buffer.includes(null) && this.dataSize != -1) {
        console.log(this.buffer);
        var res = new Uint8Array([...this.buffer]); //.sort((a, b)=>a[0]-b[0]).map((i)=>i[1][1].data).reduce((a, b)=>[...a, ...b]));
        //this.buffer.clear();
        console.log(res);
        console.log(`recieved ${this.recieved} packets`);
        this.#resolve(res);
      }
    }
  }
}



class CustomBuffer extends Array {
  constructor() {
    super();
  }
  set(index, iterable) {
    if (this.length <= index) {
      for (let i = this.length; i <= index; i++) {
        this.push(null);
      }
    }
    var iterable = [...iterable];
    //var newArray = [...this.slice(0, index), ...iterable, ...this.slice(index+iterable.length)];
    this.splice(index, iterable.length, ...iterable);
    return this;
  }
  clear() {
    this.splice(0, this.length);
  }
  ranges(s=0, e=-1) {
    var result = [];
    var start = -1;
    if (e<0) {e = this.length+e+1};
    if (e >= this.length) {e = this.length}
    for (let i = s; i <= e; i++) {
      if (this[i] != null) {
        if (start == -1) {
          start = i;
        }
      }
      if (this[i] == null || i == e){
        if (start != -1) {
          result.push([start, i-1]);
          start = -1;
        }
      }
    }
    return [...result];
  }
}

class TCPoverTLSSocket extends TCPSocket {
  constructor(...args) {
    super(...args);
    this.encrypted = false;
  }
  async handshake() {
    super.handshake();
  }
}

class UDPSocket extends NetworkSocket {
  #manager;
  #srcPort;
  #desPort;
  #desIP;
  #promise
  #resolve;
  #reject;
  constructor(manager, srcPort, desPort, desIP) {
    super();
    this.#manager = manager;
    this.#srcPort = srcPort;
    this.#desPort = desPort;
    this.#desIP = desIP;
    this.queue = [];
    this.recieved = 0;
    this.closed = false;
    this.#promise = new Promise((resolve, reject)=>{this.#resolve = resolve; this.#reject = reject;});
    this.addEventListener("message", this.handleMessage)
  }
  get srcPort() { return this.#srcPort; }
  get desPort() { return this.#desPort; }
  get desIP() { return this.#desIP; }
  async send(data) {
    var udp = new UDPFrame(network.IP, this.#srcPort, this.#desIP, this.#desPort);
    udp.data = data;
    await this.#manager.send(this, udp);
  }
  async *listen(parser) {
    if (parser == undefined) {
      parser = (e)=>e;
    }
    this.parser = parser;
    if (this.#promise == undefined) {
      this.#promise = new Promise((resolve, reject)=>{this.#resolve = resolve; this.#reject = reject;});
    }
    while (!this.closed) {
      yield await this.#promise;
    }
  }
  async get(parser) {
    if (parser == undefined) {
      parser = (e)=>e;
    }
    if (this.queue.length > 0) {
      return this.queue.shift();
    } else {
      if (this.#promise == undefined) {
        this.#promise = new Promise((resolve, reject)=>{this.#resolve = resolve; this.#reject = reject;});
      }
      return await this.#promise;
    }
  }
  async close() {
    this.closed = true;
    this.#resolve = undefined;
    this.dispatchEvent(new Event("close"));
  }
  async handleMessage(e) {
    console.log(e);
    var res = e.data;
    console.log(res);
    console.log(`recieved ${res.data.length} bytes`);
    if (this.#promise != undefined) {
      if (this.parser != undefined) {
        res.data = this.parser(res.data);
      }
      var ev = new MessageEvent("recieve", {data:res.data});
      this.dispatchEvent(ev);
      this.#resolve(res.data);
      this.#promise = new Promise((resolve, reject)=>{this.#resolve = resolve; this.#reject = reject;});
    } else {
      this.queue.push(res.data);
    }
  }
}

class Hosts {
  #hosts = new Map();
  constructor() {
    this.#hosts.set("localhost", "127.0.0.1");
  }
  setHost(domain, ipaddr) {
    this.#hosts.set(domain, ipaddr);
  }
  getHost(domain) {
    return this.#hosts.get(domain);
  }
}

class ARPTable {
  #hosts = new Map();
  constructor() {
    this.#hosts.set("127.0.0.1", network.MAC);
  }
  setHost(ipaddr, macaddr) {
    this.#hosts.set(ipaddr, macaddr);
  }
  getHost(ipaddr) {
    return this.#hosts.get(ipaddr);
  }  
}

class NameResolver {
  constructor() {
    this.hosts = new Hosts();
  }
  async resolve(domain) {
    var sock; // = socks.getUDPSocket(, 53, network.dns.IP);
    /* while (true) {
      try {
        sock = socks.getTCPSocket(Math.floor(Math.random()*4096)+4096, 53, network.dns.IP);
      } catch(ev) {
        console.log(ev);
        continue;
      }
      break;
    }
    var a = new EthernetFrame(network.gateway.MAC, network.MAC, "ipv4");
    var b = a.data = new IPFrame(4, 0, 0, 0, 0, 100, 17, network.IP, network.dns.IP);
    var c = b.data = new UDPFrame(network.IP, 123, network.dns.IP, 53); */
    var req= new DNSFrame("normal", 1, [[domain, "A", "IN"]]);
    var res;
    for (let i =0; i < network.dnss.length*2; i++) {
      while (true) {
        try {
          sock = socks.getUDPSocket(Math.floor(Math.random()*4096)+4096, 53, network.dnss[Math.floor(i/2)].IP);
        } catch(ev) {
          console.log(ev);
          continue;
        }
        break;
      }
      sock.parser = (e)=>{return DNSFrame.fromBinary(e)};
      await sock.send(req);
      try {
        /* res = (await waitUntil(ws, "message", 5000, {filter:(e)=>{
          return e.data.header.srcMAC == network.dnss[Math.floor(i/2)].MAC &&
          IPFrame.prototype.isPrototypeOf(e.data.data) &&
          UDPFrame.prototype.isPrototypeOf(e.data.data.data) &&
          DNSFrame.prototype.isPrototypeOf(e.data.data.data.data) &&
          e.data.data.data.data.header.id == d.header.id &&
          e.data.data.data.data.header.answers.some((i)=>i[1]=="A")
        }})).data; */
        res = (await waitUntil(sock, "recieve", 3000, {filter:(e)=>{
          return e.data.header.id == req.header.id && e.data.header.answers.some((i)=>i[1]=="A");
        }})).data;
        break;
      } catch {
        if (i == network.dnss.length*2-1) {
          sock.close();
          throw "Unknown domain";
        }
        continue;
      }
    }
    sock.close();
    var ipaddr = res.header.answers.find((i)=>i[1]=="A")[4].map((i)=>i.toString()).join(".");
    this.hosts.setHost(ipaddr, domain);
    return ipaddr;
  }
}



function handshake(desIP, desMAC) {
  a = new EthernetFrame(desMAC, network.MAC, "ipv4");
  a.data = b = new IPFrame(4, 0, 0, 0, 0, 0x40, 17,network.IP,desIP);
  b.data = c = new TCPFrame(100, 80, 0, 0, ["SYN"]);
  ws.send(a.build());
}

var network = new Address()
var ws;
var proxy = "wss://relay.widgetry.org";
var dns = "8.8.8.8";
var rslv = new NameResolver();
var sockets

function waitUntil(target, ev, timeout=1000, options={}) {
  if (Number.prototype != Object.getPrototypeOf(timeout)) {
    options = timeout;
    timeout = 1000;
  }
  var callback=options.callback || ((e)=>e);
  var filter = options.filter || ((e)=>true);
  var doReject = options.doReject!=undefined?options.doReject:true;
  var aws = new Promise((resolve, reject) => {
    var id = setTimeout(function() {
      target.removeEventListener(ev, resolver);
      if (doReject) {
        reject();
      } else {
        resolve();
      }
    }, timeout);
    var resolver = async function(e) {
      if (Object.getPrototypeOf(async function(){}) == Object.getPrototypeOf(filter)) {
        if (!await filter(e)) {return;}
      } else { if (!filter(e)) {return;} }
      target.removeEventListener(ev, resolver)
      if (callback) {
        resolve(callback(e));
      } else {
        resolve();
      }
      clearTimeout(id);
    }
    target.addEventListener(ev, resolver);
  });
  return aws;
}

async function requestNewIP() {
  var sock = socks.getUDPSocket(68, 67, "255.255.255.255");
  while (true) {
    network.IP = "0.0.0.0";
    // DHCP discover;
    console.log("DHCP Discover start...");
    var req = new DHCPFrame("request", 12345, 0, 0, "0.0.0.0", network.MAC, {53:"discover"});
    var res;
    sock.parser = (e)=>DHCPFrame.fromBinary(e);
    while (true) {
      try {
        await sock.send(req);
        res = (await waitUntil(sock, "recieve", 5000, {filter:(e)=>console.log(e)||e.data.header.op == 2 && e.data.header.options[53][0] == 2})).data;
        console.log(res);
        var offeredIP = res.header.yourIP;
      } catch (er) {
        console.error(er);
        console.log("Time out. Retry...");
        continue;
      }
      break;
    }
    console.log(res);
    network.DHCPServerIP = res.header.serverIP;
    console.log("IP address offered from "+network.DHCPServerIP+" : "+offeredIP);
    req = new DHCPFrame("request", 12345, 0, 0, "0.0.0.0", network.MAC, {53:"request", 55:"030633", 20: "01", 50:offeredIP.split(".").map((i)=>parseInt(i).toString(16).padStart(2, "0")).join(""), 54:res.header.srcIP.split(".").map((i)=>parseInt(i).toString(16).padStart(2, "0")).join("")});
    await sock.send(req);
    console.log("Requesting new IP address : "+offeredIP);
    network.IP = offeredIP;
    console.log("Request succeed");
    break;
  }
  console.log(res);
  network.lease = new Date(Date.now() + res.header.options[51].reduce((i, i2)=>(i<<8)|i2)*1000);
  console.log(`The IP address will be disabled on ${network.lease.toString()}`);
  network.subnet = res.header.options[1].map((i)=>i.toString()).join(".");
  console.log("Subnet: "+network.subnet);
  network.gateway = new Address();
  network.gateway.IP = res.header.options[3].map((i)=>i.toString()).join(".");
  console.log("Gateway IP: "+network.gateway.IP);
  network.dnss = [];
  for (let i=0; i < res.header.options[6].length; i+=4) {
    network.dnss.push(new Address());
    network.dnss.at(-1).IP = res.header.options[6].slice(i, i+4).map((i)=>i.toString()).join(".");
    console.log("DNS server IP: "+network.dnss.at(-1).IP);
  }
  if (res.header.options[58]) {
    network.renewalAfter = res.header.options[58].reduce((i, i2)=>(i<<8)|i2)*1000;
  } else {
    network.renewalAfter = res.header.options[51].reduce((i, i2)=>(i<<8)|i2)*500;
  }
  setTimeout(requestRenewal, network.renewalAfter);
}

async function requestRenewal() {
  var sock = socks.getUDPSocket(68, 67, "255.255.255.255");
  while (true) {
    network.IP = "0.0.0.0";
    // DHCP discover;
    console.log("DHCP Discover start...");
    var req = new DHCPFrame("request", 12345, 0, 0, "0.0.0.0", network.MAC, {53:"discover"});
    var res;
    sock.parser = (e)=>DHCPFrame.fromBinary(e);
    while (true) {
      try {
        await sock.send(req);
        res = (await waitUntil(sock, "recieve", 5000, {filter:(e)=>console.log(e)||e.data.header.op == 2 && e.data.header.options[53][0] == 2})).data;
        console.log(res);
        var offeredIP = res.header.yourIP;
      } catch (er) {
        console.error(er);
        console.log("Time out. Retry...");
        continue;
      }
      break;
    }
    console.log(res);
    network.DHCPServerIP = res.header.serverIP;
    console.log("IP address offered from "+network.DHCPServerIP+" : "+offeredIP);
    req = new DHCPFrame("request", 12345, 0, 0, "0.0.0.0", network.MAC, {53:"request", 55:"030633", 20: "01", 50:offeredIP.split(".").map((i)=>parseInt(i).toString(16).padStart(2, "0")).join(""), 54:res.header.srcIP.split(".").map((i)=>parseInt(i).toString(16).padStart(2, "0")).join("")});
    await sock.send(req);
    console.log("Requesting new IP address : "+offeredIP);
    network.IP = offeredIP;
    console.log("Request succeed");
    break;
  }
  while (true) {
    a = new EthernetFrame("ff:ff:ff:ff:ff:ff", network.MAC, "ipv4");
    a.data = b = new IPFrame(4, 0, 0, 0, 0, 0x40, 17,network.IP,"255.255.255.255");
    b.data = c = new UDPFrame(network.IP, 68,"255.255.255.255",67);
    c.data = d = new DHCPFrame("request", 12345, Math.floor((network.lease - Date.now())/1000), 0, network.IP, network.MAC, {53:"request", 55:"333a3b", 50:network.IP.split(".").map((i)=>parseInt(i).toString(16).padStart(2, "0")).join(""), 54:network.DHCPServerIP.split(".").map((i)=>parseInt(i).toString(16).padStart(2, "0")).join("")});
    ws.send(a.build());
    console.log("Re-requesting IP address : "+network.IP);
    var res;
    await waitUntil(ws, "message", 5000, {filter:(e)=>{
      if (network.MAC == e.data.header.desMAC && e.data.header.protocol == protocols.IPv4) {
        e.data.data = IPFrame.fromBinary(e.data.data);
        e.data.data.data = UDPFrame.fromBinary(e.data.data.data);
        e.data.data.data.data = DHCPFrame.fromBinary(e.data.data.data.data);
        if (e.data.data.data.data.header.op == 2 && e.data.data.data.data.header.options[53][0] == 5) {
          res = e;
          return true;
        }
      }
    }, doReject:false});
    ;
    console.log("Re-request succeed");
    break;
  }
  console.log(res);
  network.lease = new Date(Date.now() + res.data.data.data.data.header.options[51].reduce((i, i2)=>(i<<8)|i2)*1000);
  console.log(`The IP address will be disabled on ${network.lease.toString()}`);
  if (res.data.data.data.data.header.options[58]) {
    network.renewalAfter = res.data.data.data.data.header.options[58].reduce((i, i2)=>(i<<8)|i2)*1000;
  } else {
    network.renewalAfter = res.data.data.data.data.header.options[51].reduce((i, i2)=>(i<<8)|i2)*500;
  }
  setTimeout(requestRenewal, network.renewalAfter);
}

async function setupNetwork() {
  console.log("connecting to proxy...");
  ws = new WebSockProxy(proxy);
  await waitUntil(ws, "open");
  console.log("done")
  socks = new NetworkSocketManager(ws);
  console.log("Making MAC...")
  while (true) {
    network.MAC = Math.floor(Math.random() * 255).toString(16).padStart(2, "0") + ":" + Math.floor(Math.random() * 255).toString(16).padStart(2, "0") + ":" + Math.floor(Math.random() * 255).toString(16).padStart(2, "0") + ":" + 
      Math.floor(Math.random() * 255).toString(16).padStart(2, "0") + ":" + Math.floor(Math.random() * 255).toString(16).padStart(2, "0") + ":" + Math.floor(Math.random() * 255).toString(16).padStart(2, "0");
    break;
  }
  console.log("Set MAC to "+network.MAC);
  await requestNewIP();
  /* var a = new EthernetFrame("ff:ff:ff:ff:ff:ff", network.MAC, "arp");
  a.data = new ARPFrame("ipv4", 6, 4, 1, network.MAC, network.IP, "00:00:00:00:00:00", network.gateway.IP);
  ws.send(a.build()); */
  while (true) {
    try {
      network.gateway.MAC = await socks.doARP(network.gateway.IP);
    } catch {
      continue;
    }
    break;
  }
  console.log("Gateway MAC: "+network.gateway.MAC);
  for (let i of network.dnss) {
    if (i.IP.split(".").reduce((i, i2)=>{return (i<<8)|parseInt(i2)})&network.subnet.split(".").reduce((i, i2)=>{return (i<<8)|parseInt(i2)}) == i.IP.split(".").reduce((i, i2)=>{return (i<<8)|parseInt(i2)})) {
    } else {
      i.MAC = network.gateway.MAC;
      continue;
    }
    /* var a = new EthernetFrame("ff:ff:ff:ff:ff:ff", network.MAC, "arp");
    a.data = new ARPFrame("ipv4", 6, 4, 1, network.MAC, network.IP, "00:00:00:00:00:00", network.dns.IP);
    ws.send(a.build());
    while (true) {
      try {
        var res = await waitUntil(ws, "message", 5000, {filter:(e)=>{return network.MAC == e.data.header.desMAC && network.dns.IP == ARPFrame.fromBinary(e.data.data).header.srcIP}});
      } catch {
        continue;
      }
      break;
    } */
    try {
      i.MAC = await socks.doARP(i.IP);
    } catch {}
    console.log("DNS server MAC: "+i.MAC);
  }
  network.dns = network.dnss[0];
  ws.addEventListener("message", (e)=>{
    if (e.data.header.desMAC == network.MAC) {
      console.log(e);
    }
    /* if (e.data.protocol == protocols.ARP) {
      e.data.data = ARPFrame.fromBinary(e.data.data)
      if (e.data.data.header.opcode == 1 && e.data.header.srcMAC != network.MAC) {
        if (e.data.data.header.desMAC == network.MAC || e.data.data.header.desIP == network.IP) {
          var a = EthernetFrame.fromBinary(e.data.build());
          a.header.desMAC = a.header.srcMAC;
          a.header.srcMAC = network.MAC;
          a.data.header.opcode = 2;
          a.data.header.srcMAC = network.MAC;
          a.data.header.srcIP = network.IP;
          a.data.header.desMAC = e.data.data.header.srcMAC;
          a.data.header.desIP = e.data.data.header.srcIP;
          ws.send(a.build());
        }
      }
    } */
  });
  console.log("done")
}

//window.addEventListener("load", setupNetwork);


async function ffetch(uri, options) {
  uri = new URL(uri);
  var request = new HTTPRequestFrame(uri, options);
  ipaddr = await rslv.resolve(uri.hostname);
  console.log(ipaddr);
  var sock;
  while (true) {
    try {
      sock = socks.getTCPSocket(Math.floor(Math.random()*4096)+4096, 80, ipaddr);
    } catch(ev) {
      console.log(ev);
      continue;
    }
    break;
  }
  await sock.handshake();
  await sock.send(request.build());
  sock.addEventListener("progress", (e)=>{
    console.log(e);
    if (e.total != undefined && e.loaded != undefined && e.lengthComputable) {
      document.getElementById("load-progress-bar").style.width = `${100*e.loaded/e.total}%`;
      if (document.getElementById("load-progress-bar").style.animationName == "") {
        document.getElementById("load-progress-bar").style.animationName = "none";
      }
    }
  })
  var res = await (await sock.listen()).next(); //console.log(await sock.listen());
  console.log(res);
  var res = HTTPResponseFrame.fromBinary(res.value);
  var result = res.options.payload;
  var mime = res.options["Content-Type"].match(/^(?<top>[^\/]+)\/(?<sub>[^\/ ]+)(?:; *)?(?:charset=(?<charset>[^ ;]+))?(?:; *)?$/).groups;
  if (mime.top == "text") {
    result = (new TextDecoder(mime.charset || "utf-8")).decode(res.options.payload);
  }
  return result;
}