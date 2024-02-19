window.indexedDB = window.indexedDB || window.mozIndexedDB || window.webkitIndexedDB || window.msIndexedDB;
window.IDBTransaction = window.IDBTransaction || window.webkitIDBTransaction || window.msIDBTransaction || {READ_WRITE: "readwrite"};
window.IDBKeyRange = window.IDBKeyRange || window.webkitIDBKeyRange || window.msIDBKeyRange;

async function setup() {
  var dbev = window.indexedDB.open("sykle-data", 1);
  dbev.onsuccess = (e)=>{
    console.log(e);
  };
  //dir = window.showDirectoryPicker({mode:"readwrite"});
  await setupNetwork();
}
function decodeObject(obj, ...args) {
  if (Object.prototype != Object.getPrototypeOf(obj)) { return obj; }
  var result = {};
  for (let i of Object.keys(obj)) {
    if ((obj[i] != undefined && obj[i] != null) && Object.prototype == Object.getPrototypeOf(obj)) {
      result[i] = decodeObject(obj[i]);
    } else {
      result[i] = obj[i];
    }
  }
  console.log(obj);
  if (obj.protoName != undefined) {
    try {
      result = new window[obj.protoName](...args, result);
    } catch(er) {
      console.log(er);
    }
  }
  return result;
}

window.addEventListener("message", (e) => {
  if (e.source != frames[0]) {
    return;
  }
  if (e.data === true) {
    console.log("connect to iframe succeed.");
    return;
  }
  if (e.data[0] == "event") {
    e.data[1] = decodeObject(e.data[1], e.data[1].type);
    var evclass = Event;
    if ((e.data[1].protoName || "").endsWith("Event")) {
      try {
        evclass = window[e.data[1].protoName];
      } catch {
        ;
      }
    }
    var ev = e.data[1]; //new evclass(e.data[1].type, e.data[1]);
    (document.getElementById("view-frame")).dispatchEvent(ev);
    console.log(ev);
  }
});

window.addEventListener("load", ()=>{
  document.getElementById("view-frame").addEventListener("load", (e) => {
    frames[0].postMessage({type:"connect"}, "*");
  });
  document.getElementById("view-frame").addEventListener("navigate", (e)=>{
    console.log(e);
  });
});
window.onload = setup;