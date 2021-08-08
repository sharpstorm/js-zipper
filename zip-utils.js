var readShort, readInt, readLong, readString, readByteArray, writeShort, writeInt, writeLong, writeString, hasUtf8, arrToString; //Bit Tools

const META_LENGTH = 8;
const CHUNK_SIZE = 5 * 1024 * 1024; //5mb

const LOCAL_FILE_HEADER_SIG = [80, 75, 3, 4];
const CENTRAL_DIRECTORY_SIG = [80, 75, 1, 2];
const END_OF_CENTRAL_DIRECTORY_SIG = [80, 75, 5, 6]; //0x50 0x4B 0x05 0x06

const AES_EXTRA_SIG = [1, 153];

const COMPRESSION_METHOD = {
  NO_COMPRESSION: 0,
  SHRUNK: 1, //LZW
  REDUCED_FACTOR_1: 2, //RLE + Probabilistic
  REDUCED_FACTOR_2: 3,
  REDUCED_FACTOR_3: 4,
  REDUCED_FACTOR_4: 5,
  IMPLODE: 6,
  RESERVED1: 7,
  DEFLATE: 8,
  DEFLATE64: 9,
  PKWARE_DCL_IMPLODED: 10,
  RESERVED2: 11,
  BZIP2: 12,
  RESERVED3: 13,
  LZMA: 14,
  RESERVED4: 15,
  RESERVED5: 16,
  RESERVED6: 17,
  IBM_TERSE: 18,
  IBM_LZ77: 19,
  PPMd: 98,
  CUSTOM: 99
};

const GP_FLAG = {
  ENCRYPTED_FILE: 1,
  COMPRESSION_1: 2,
  COMPRESSION_2: 4,
  DATA_DESCRIPTOR: 8,
  ENHANCED_DEFLATE: 16,
  COMPRESSED_PATCHED_DATA: 32,
  STRONG_ENCRYPTION: 64,
  IS_UTF8: 2048,
  RESERVED: 4096,
  MASK_HEADER_VALUES: 8192
};

const AES_STRENGTH = {
  AES128: 1,
  AES192: 2,
  AES256: 3
}

const AESSaltLength = [-1, 8, 12, 16];
const AESKeyLength = [-1, 16, 24, 32];

const ENCRYPT_MODE = {
  AES: 0,
  ZIPCRYPTO: 1
}

class Archive {
  constructor(ft, file) {
    this.fileTable = ft;
    this.file = file;
    if (this.fileTable == undefined) {
      this.fileTable = new CentralDirectory();
    }
  }

  async export(encrypted, encryptMode, password) {
    if (encrypted === undefined) {
      encrypted = false;
    }
    if (encrypted === true && (encryptMode === undefined || encryptMode < 0 || encryptMode > 1 || password === undefined || password === '')) {
      encrypted = false;
    }

    const centralDir = this.fileTable;
    centralDir.fillFromDirectoryTree();

    const exportContents = [];
    let positionPointers = [];
    let curPosition = 0;

    for (const curRecord of centralDir.fileRecords) {
      if (curRecord.localFileHeader === undefined) {
        return;
      }

      // Is a file, Perform Compression
      const localFile = curRecord.localFileHeader
      if (!localFile.isCompressed) {
        localFile.dataBlob = pako.deflateRaw(localFile.dataBlob);
        localFile.isCompressed = true;
        localFile.compressionMethod = COMPRESSION_METHOD.DEFLATE;
        localFile.compressedSize = localFile.dataBlob.length;

        curRecord.compressionMethod = COMPRESSION_METHOD.DEFLATE;
        curRecord.compressedSize = localFile.dataBlob.length;
      }

      // Write position to tracking array
      positionPointers.push(curPosition);

      // Write Local File Header
      let localHeader;
      if (encrypted) {
        console.log(`Writing encrypted header ${encryptMode}`);
        localHeader = localFile.writeEncryptedHeader(encryptMode);
        CentralDirectory.copyRecord(curRecord, curRecord.localFileHeader);
      } else {
        localHeader = localFile.writeHeader();
      }

      curPosition += localHeader.length;
      exportContents.push(localHeader);

      // Write File Data
      if (encrypted) {
        if (encryptMode === ENCRYPT_MODE.AES) {
          const salt = new Uint8Array(AESSaltLength[AES_STRENGTH.AES256]);
          window.crypto.getRandomValues(salt);
          const expandedPwd = new Uint8Array(await pbkdf2('SHA-1', salt, password, 1000, 66));
          const key = new Uint8Array(expandedPwd.slice(0, AESKeyLength[AES_STRENGTH.AES256]));
          const authKey = new Uint8Array(expandedPwd.slice(AESKeyLength[AES_STRENGTH.AES256], AESKeyLength[AES_STRENGTH.AES256] * 2));
          
          exportContents.push(salt);
          exportContents.push(new Uint8Array([expandedPwd[64], expandedPwd[65]]));
          const encData = await AESEncrypt(curRecord.localFileHeader.dataBlob, key);
          exportContents.push(encData);
          exportContents.push((await hmacHash(authKey, encData)).slice(0, 10));
          curPosition += curRecord.localFileHeader.dataBlob.length + salt.length + 12;

        } else if (encryptMode === ENCRYPT_MODE.ZIPCRYPTO) {
          const cryptoWorker = new ZipCryptoWorker(password);

          //Write Stream Initialiser
          const initBytes = new Uint8Array(12);
          window.crypto.getRandomValues(initBytes);
          initBytes[11] = (curRecord.localFileHeader.crc32 >> 24) & 255;
          const encryptedInit = cryptoWorker.encrypt(initBytes);
          exportContents.push(encryptedInit);

          const encryptedContents = cryptoWorker.encrypt(curRecord.localFileHeader.dataBlob);
          exportContents.push(encryptedContents);

          curPosition += curRecord.localFileHeader.dataBlob.length + 12;
        }
        
      } else {
        exportContents.push(curRecord.localFileHeader.dataBlob);
        curPosition += curRecord.localFileHeader.dataBlob.length;
      }
    }

    // Write Central Directory
    let centralDirSize = 0;
    centralDir.fileRecords.forEach((record, idx) => {
      const recordBinary = record.writeRecord(positionPointers[idx]);
      exportContents.push(recordBinary);
      centralDirSize += recordBinary.length;
    });

    //Write end of centralDirectory
    exportContents.push(centralDir.exportEndOfCentralDirectory(centralDirSize, curPosition));
    return new Blob(exportContents, {type: 'application/zip'});
  }

  static async from(file) {
    try {
      const archive = await Archive.scanForCentralDirectory(file);
      await archive.fileTable.parseLocalFileHeaders();
      await archive.fileTable.resolveDirectoryTree();
      return archive;
    } catch (err) {
      throw new Error(err);
    }
  }

  static async scanForCentralDirectory(file) {
    const CHUNK_SIZE = 65536;
    let end = file.size;

    while (end > 0) {
      const start = (end-CHUNK_SIZE >= 0) ? end-CHUNK_SIZE : 0;
      const result = new Uint8Array(await readFile(file, start, end));
      const dirIdx = searchByteArray(result, END_OF_CENTRAL_DIRECTORY_SIG);

      if (dirIdx >= 0) {
        // Found Signature
        const header = new Uint8Array(await readFile(file, start + dirIdx, start + dirIdx + 20));
        const size = readInt(header, 12);
        const offset = readInt(header, 16);
        console.log(size, offset);

        let centralDir;
        try {
          centralDir = await CentralDirectory.from(file, offset, size);
        } catch {
          throw new Error('Failed to parse central directory');
        }
        if (centralDir === undefined) {
          throw new Error('Failed to parse central directory');
        }
        return new Archive(centralDir, file);
      } else {
        end -= CHUNK_SIZE - 4; //Overlap
      }
    }
    throw new Error('Central Directory Not Found');
  }
}

class CentralDirectory {
  constructor(file) {
    this.file = file;
    this.fileRecords = [];
    this.fileTree = {};
  }

  parseLocalFileHeaders() {
    return Promise.all(this.fileRecords.map((x) => x.parseLocalFileHeader(this.file)));
  }

  resolveDirectoryTree() {
    this.fileRecords.forEach((record) => {
      let parentTree = record.getParentTree();
      let curFolder = this.fileTree;
      parentTree.forEach((folder) => {
        if (!(folder in curFolder)) {
          curFolder[folder] = {};
        }
        curFolder = curFolder[folder];
      });

      if (record.getName() !== '') {
        curFolder[record.getName()] = record.localFileHeader;
      }
    });
  }

  // Flattens the tree into an array
  fillFromDirectoryTree() {
    this.fileRecords = [];
    this.fillTreeNode(this.fileTree, '');
  }

  fillTreeNode(node, curPath) {
    const keys = Object.keys(node);
    keys.forEach((name) => {
      const item = node[name];
      const record = new CentralFileRecord();
      if (item instanceof File) {
        record.fileName = curPath + name;
        record.lastModified = item.lastModified;
        record.uncompressedSize = item.uncompressedSize;
        record.crc32 = item.crc32;
        record.localFileHeader = item;
        this.fileRecords.push(record);
      } else {
        record.fileName = curPath;
        this.fileRecords.push(record);
        this.fillTreeNode(item, curPath + name + '/');
      }
    });
  }

  exportEndOfCentralDirectory(size, offset) {
    let ret = END_OF_CENTRAL_DIRECTORY_SIG.map((x) => x); // Clone Signature
    ret = ret.concat(
      writeShort(0),
      writeShort(0),
      writeShort(this.fileRecords.length),
      writeShort(this.fileRecords.length),
      writeInt(size),
      writeInt(offset),
      writeShort(0)
    );

    return new Uint8Array(ret);
  }

  static copyRecord(centralRecord, localRecord) {
    centralRecord.flags = localRecord.flags;
    centralRecord.lastModified = localRecord.lastModified;
    centralRecord.uncompressedSize = localRecord.uncompressedSize;
    centralRecord.compressedSize = localRecord.compressedSize;
    centralRecord.crc32 = localRecord.crc32;
  }

  static async from(file, offset, size) {
    const data = await readFile(file, offset, offset + size);
    const result = new Uint8Array(data);
    const centralDirectory = new CentralDirectory(file);

    for (let pointer = 0; pointer < size; pointer++) {
      const record = CentralFileRecord.from(result, pointer);
      if (record === undefined) {
        continue;
      }

      pointer += record.size - 1; // -1 because the loop will do a +1
      centralDirectory.fileRecords.push(record.record);
    }

    console.log(`Read ${centralDirectory.fileRecords.length} files`);
    
    return centralDirectory;
  }
}

class CentralFileRecord {
  constructor() {
    this.compressionMethod = COMPRESSION_METHOD.NO_COMPRESSION;
    this.flags = 0;
    this.lastModified = 0;
    this.crc32 = undefined;
    this.compressedSize = 0;
    this.uncompressedSize = 0;
    this.internalFileAttributes = 0;
    this.externalFileAttributes = 0;
    this.fileName = undefined;
    this.extra = undefined;
    this.comment = undefined;

    this.fileOffset = -1;
    this.localFileHeader = undefined;
  }

  async parseLocalFileHeader(file) {
    if (this.fileOffset < 0) {
      return;
    }

    this.localFileHeader = await File.readHeader(file, this.fileOffset);
  }

  writeRecord(offset) {
    let ret = CENTRAL_DIRECTORY_SIG.map((x) => x); // Clone Signature

    const dateTime = encodeZipDateTime(this.lastModified);
    let fNameEncoded;
    if (hasUtf8(this.fileName)) {
      fNameEncoded = encodeString(this.fileName, true);
      this.flags |= GP_FLAG.IS_UTF8;
    } else {
      fNameEncoded = encodeString(this.fileName);
      if (this.flags & GP_FLAG.IS_UTF8 === GP_FLAG.IS_UTF8) {
        this.flags -= GP_FLAG.IS_UTF8;
      }
    }

    ret = ret.concat(
      writeShort(63),                              // Version
      writeShort(10),                              // Version Needed
      writeShort(this.flags),                      // Flags
      writeShort(this.compressionMethod),          // Compression Method
      writeShort(dateTime[1]),                     // Mod Time
      writeShort(dateTime[0]),                     // Mod Date
      writeInt(this.crc32),                        // CRC32
      writeInt(this.compressedSize),               // Compressed Size
      writeInt(this.uncompressedSize),             // Uncompressed Size
      writeShort(fNameEncoded.length),             // File Name Len
      writeShort(0),                               // Extra Len
      writeShort(0),                               // Comment Len
      writeShort(0),                               // Disk Start
      writeShort(this.internalFileAttributes),     // Internal Attrs
      writeInt(this.externalFileAttributes),       // External Attrs
      writeInt(offset),                            // Offset
      fNameEncoded
    );

    return new Uint8Array(ret);
  }

  getParentTree() {
    const parts = this.fileName.split('/');
    return parts.slice(0, parts.length - 1);
  }

  getName() {
    const parts = this.fileName.split('/');
    return parts[parts.length - 1];
  }

  static from(data, pointer) {
    // Validate Signature
    const isValid = CENTRAL_DIRECTORY_SIG.every((x, idx) => data[pointer + idx] === x);
    if (!isValid) {
      return undefined;
    }

    const centralFile = new CentralFileRecord();
    const ver = readShort(data, pointer + 4);
    const minVer = readShort(data, pointer + 6);
    centralFile.flags = readShort(data, pointer + 8);
    centralFile.compressionMethod = readShort(data, pointer + 10);
    const lastModTime = readShort(data, pointer + 12);
    const lastModDate = readShort(data, pointer + 14);
    centralFile.lastModified = decodeZipDateTime(lastModTime, lastModDate);
    centralFile.crc32 = readInt(data, pointer + 16);
    centralFile.compressedSize = readInt(data, pointer + 20);
    centralFile.uncompressedSize = readInt(data, pointer + 24);
    const fileNameLen = readShort(data, pointer + 28);
    const extraLen = readShort(data, pointer + 30);
    const commentLen = readShort(data, pointer + 32);
    const startDisk = readShort(data, pointer + 34); //Ignore
    centralFile.internalFileAttributes = readShort(data, pointer + 36);
    centralFile.externalFileAttributes = readInt(data, pointer + 38);
    centralFile.fileOffset = readInt(data, pointer + 42);

    if ((centralFile.flags & GP_FLAG.IS_UTF8) === GP_FLAG.IS_UTF8) {
      centralFile.fileName = decodeEncodedString(data, pointer + 46, true, pointer + 46 + fileNameLen);
    } else {
      centralFile.fileName = decodeEncodedString(data, pointer + 46, false, pointer + 46 + fileNameLen);
    }

    centralFile.extra = decodeEncodedString(data, pointer + 46 + fileNameLen, false, pointer + 46 + fileNameLen + extraLen);
    centralFile.comment = decodeEncodedString(data, pointer + 46 + fileNameLen + extraLen, false, pointer + 46 + fileNameLen + extraLen + commentLen);

    return {
      record: centralFile,
      size: 46 + fileNameLen + extraLen + commentLen,
    };
  }
}

class File {
  constructor(file) {
    this.file = file;

    this.flags = 0;
    this.compressionMethod = COMPRESSION_METHOD.NO_COMPRESSION;
    this.lastModified = 0;
    this.crc32 = undefined;
    this.compressedSize = 0;
    this.uncompressedSize = 0;
    this.fileName = undefined;
    this.extra = undefined;

    this.dataOffset = -1;

    this.isCached = false;
    this.isCompressed = false;
    this.dataBlob = undefined;
  }

  isAESEncrypted() {
    return (this.compressionMethod === 99) && ((this.flags & GP_FLAG.ENCRYPTED_FILE) === GP_FLAG.ENCRYPTED_FILE);
  }

  isZipCryptoEncrypted() {
    return (this.flags & GP_FLAG.ENCRYPTED_FILE) === GP_FLAG.ENCRYPTED_FILE;
  }

  isEncrypted() {
    return this.isAESEncrypted() || this.isZipCryptoEncrypted();
  }

  extract(password) {
    if(this.isCached)
      return this.extractCached();
    
    if(this.isAESEncrypted())
      return this.extractAES(password);
    else if(this.isZipCryptoEncrypted())
      return this.extractZipCrypto(password);
    else
      return this.extractUnprotected();
  }

  async extractUnprotected() {
    const result = new Uint8Array(await readFile(this.file, this.dataOffset, this.dataOffset + this.compressedSize));
    if (this.compressionMethod === COMPRESSION_METHOD.DEFLATE) {
      return pako.inflateRaw(result);
    }
  }

  async extractZipCrypto(password) {
    const decryptWorker = new ZipCryptoWorker(password);

    const header = new Uint8Array(await readFile(this.file, this.dataOffset, this.dataOffset + 12));
    const headerDecode = decryptWorker.decrypt(header);
    if (headerDecode[11] !== ((this.crc32 >> 24) & 255)) {
      throw new Error('Incorrect Password');
    }

    // Correct Password (Probably because CRC isnt a 100% check)
    const data = new Uint8Array(await readFile(this.file, this.dataOffset + 12, this.dataOffset + this.compressedSize));
    const decryptedData = decryptWorker.decrypt(data);
    if (this.compressionMethod === COMPRESSION_METHOD.DEFLATE) {
      let uncompressed;
      try {
        uncompressed = pako.inflateRaw(decryptedData);
      } catch (err) {
        console.log(err);
        throw new Error('Unable to Decompress data');
      }
      return uncompressed;
    }
    return decryptedData;
  }

  async extractAES(password) {
    // Read Extra Field
    const isValid = AES_EXTRA_SIG.every((x, idx) => this.extra[idx] === x);
    if (!isValid) {
      throw new Error('Invalid AES Extra Signature');
    }

    const AESExtraLen = readShort(this.extra, 2);
    if (AESExtraLen !== 7) {
      throw new Error('Invalid AES Extra Length');
    }

    const aesVer = readShort(this.extra, 4);
    const vendorId = readShort(this.extra, 6);
    const AESStrength = this.extra[8];
    const compressionMethod = readShort(this.extra, 9);

    const saltLen = AESSaltLength[AESStrength];
    const encryptedCompressedFileSize = this.compressedSize - saltLen - 12; //Encryption performed on compresed data, 12 = 2(Verify) + 10(Tail Auth Code)

    const aesHeader = new Uint8Array(await readFile(this.file, this.dataOffset, this.dataOffset + saltLen + 2));
    const salt = aesHeader.slice(0, saltLen);
    const verifyCheck = aesHeader.slice(saltLen);

    const privateKey = new Uint8Array(await pbkdf2('SHA-1', salt, password, 1000, 66));
    // Verify Password Using Check Bytes
    if (verifyCheck[0] !== privateKey[64] || verifyCheck[1] !== privateKey[65]) {
      throw new Error('Invalid Password');
    }

    const data = new Uint8Array(await readFile(this.file, this.dataOffset + saltLen + 2, this.dataOffset + saltLen + 2 + encryptedCompressedFileSize));
    const compressedPlaintext = await AESDecrypt(data, privateKey.slice(0, AESKeyLength[AESStrength]));
    if (compressionMethod === COMPRESSION_METHOD.DEFLATE) {
      let uncompressed;
      try {
        uncompressed = pako.inflateRaw(compressedPlaintext);
      } catch (err) {
        throw new Error('Failed to Inflate Data');
      }
      return uncompressed;
    }
    return compressedPlaintext;
  }

  async extractCached() {
    if (this.isCompressed) {
      return pako.inflateRaw(this.dataBlob);
    }
    return this.dataBlob;
  }

  writeHeader() {
    let ret = LOCAL_FILE_HEADER_SIG.map((x) => x);

    const dateTime = encodeZipDateTime(this.lastModified);
    let fNameEncoded;
    if (hasUtf8(this.fileName)) {
      fNameEncoded = encodeString(this.fileName, true);
      this.flags |= GP_FLAG.IS_UTF8;
    } else {
      fNameEncoded = encodeString(this.fileName);
      if ((this.flags & GP_FLAG.IS_UTF8) === GP_FLAG.IS_UTF8) {
        this.flags -= GP_FLAG.IS_UTF8;
      }
    }
    const extraLen = (this.extra === undefined) ? 0 : this.extra.length;
    
    ret = ret.concat(
      writeShort(10),                       // Version
      writeShort(this.flags),               // Flags
      writeShort(this.compressionMethod),   // Compression Method
      writeShort(dateTime[1]),              // Last Modified Time
      writeShort(dateTime[0]),              // Last Modified Date
      writeInt(this.crc32),                 // CRC32
      writeInt(this.compressedSize),        // Compressed Size in Bytes
      writeInt(this.uncompressedSize),      // Uncompressed Size in Bytes
      writeShort(fNameEncoded.length),      // File Name Length
      writeShort(extraLen),                 // Extra Length
      fNameEncoded,                         // File Name
    );

    if (this.extra !== undefined) {
      ret = ret.concat(Array.from(this.extra));
    }

    return new Uint8Array(ret);
  }

  writeEncryptedHeader(encryptMode) {
    if ((this.flags & GP_FLAG.ENCRYPTED_FILE) !== GP_FLAG.ENCRYPTED_FILE) {
      this.flags += GP_FLAG.ENCRYPTED_FILE;

      if (encryptMode === ENCRYPT_MODE.AES && this.compressionMethod !== 99) {
        // AES Header
        let trueCompressionMethod = this.compressionMethod;
        this.compressionMethod = 99;
        this.crc32 = 0;
        this.compressedSize += AESSaltLength[AES_STRENGTH.AES256] + 12;

        //Build Extra
        let extra = AES_EXTRA_SIG.map((x) => x);
        extra = extra.concat(
          writeShort(7), // AES Length
          writeShort(2), // AES Version
          writeShort(17729), // Vendor ID
          [AES_STRENGTH.AES256],
          writeShort(trueCompressionMethod)
        );
        this.extra = new Uint8Array(extra);
      
      } else if (encryptMode === ENCRYPT_MODE.ZIPCRYPTO) {
        // Zip Crypto Header
        this.compressedSize += 12;
      }
    }
    return this.writeHeader();
  }

  static async readHeader(file, offset) {
    const result = new Uint8Array(await readFile(file, offset, offset + 30));
    const localFileHeader = new File();
    localFileHeader.file = file;
    
    // Validate Signature
    const isValid = LOCAL_FILE_HEADER_SIG.every((x, idx) => result[idx] === x);
    if (!isValid) {
      throw new Exception('Invalid File Header');
    }

    const version = readShort(result, 4);
    localFileHeader.flags = readShort(result, 6);
    localFileHeader.compressionMethod = readShort(result, 8);
    
    const lastModTime = readShort(result, 10);
    const lastModDate = readShort(result, 12);
    localFileHeader.lastModified = decodeZipDateTime(lastModTime, lastModDate);
    localFileHeader.crc32 = readInt(result, 14);
    localFileHeader.compressedSize = readInt(result, 18);
    localFileHeader.uncompressedSize = readInt(result, 22);
    const fNameLen = readShort(result, 26);
    const extraLen = readShort(result, 28);

    const result2 = new Uint8Array(await readFile(file, offset + 30, offset + 30 + fNameLen + extraLen));
    localFileHeader.fileName = decodeEncodedString(result2, 0, localFileHeader.flags & GP_FLAG.IS_UTF8 === GP_FLAG.IS_UTF8, fNameLen);
    localFileHeader.extra = readByteArray(result2, fNameLen, fNameLen + extraLen);
    localFileHeader.dataOffset = offset + 30 + fNameLen + extraLen;

    return localFileHeader;
  }

  static async fromUpload(file) {
    const result = new Uint8Array(await readFile(file, 0, file.size));
    const ret = new File();
    ret.dataBlob = result;
    ret.isCached = true;
    ret.uncompressedSize = file.size;
    ret.fileName = file.name;
    ret.crc32 = fileCrc32(result);
    ret.lastModified = file.lastModifiedDate;

    return ret;
  }
}

function initFileReader() {
  if (fileReader === undefined) {
    fileReader = new FileReader();
  }
}

const readQueue = [];
let readBusy = false;

function readFile(file, start, end) {
  if (readBusy) {
    return new Promise((resolve) => {
      readQueue.push([file, start, end, resolve]);
    });
  }

  //Is free
  initFileReader();
  return new Promise((resolve) => {
    readBusy = true;
    fileReader.onloadend = function() {
      readBusy = false;
      const res = fileReader.result;
      resolve(res);
      if(readQueue.length > 0){
        const task = readQueue.shift();
        readFile(task[0], task[1], task[2]).then(task[3]);
      }
    }
    var chunk = file.slice(start, end);
    fileReader.readAsArrayBuffer(chunk);
  });
}

function searchByteArray(arr, match){
  for(let i=0;i<arr.length;i++){
    for(let j=0;j<match.length;j++){

      if(arr[i + j] !== match[j]) break;

      if(j >= match.length - 1) return i;
    }
  }
  return -1;
}

function AESDecrypt(data, key){
  return new Promise((resolve) => {
    var aesCtr = new aesjs.ModeOfOperation.ctr(key, new aesjs.Counter([1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]));
    var plain = aesCtr.decrypt(data);
    resolve(plain);
  });
}

function AESEncrypt(data, key){
  return new Promise((resolve) => {
    var aesCtr = new aesjs.ModeOfOperation.ctr(key, new aesjs.Counter([1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]));
    var cipher = aesCtr.encrypt(data);
    resolve(cipher);
  });
}

class ZipCryptoWorker {
  constructor(password) {
    this.password = password;
    this.key0 = 0x12345678;
    this.key1 = 0x23456789;
    this.key2 = 0x34567890;
    for (let i = 0; i < password.length; i += 1) {
      this.updateKeys(password.charCodeAt(i));
    }
  }

  updateKeys(char) {
    this.key0 = crc32Inverse(char, this.key0);
    this.key1 = getInt32(this.key1 + (this.key0 & 255));
    this.key1 = getInt32(Math.imul(this.key1, 134775813) + 1);
    this.key2 = crc32Inverse(((this.key1 >>> 24) & 255), this.key2);
  }

  decrypt(data) {
    const output = new Uint8Array(data.length);
    for (let i = 0; i < data.length; i += 1) {
      const temp = this.key2 | 2;
      const decryptByte = (Math.imul(temp, (temp ^ 1)) >> 8) & 255;
      const C = (decryptByte ^ data[i]) & 255;
      this.updateKeys(C);
      output[i] = C;
    }
    return output;
  }

  encrypt(data) {
    const output = new Uint8Array(data.length);
    for (let i = 0; i < data.length; i += 1) {
      const temp = this.key2 | 2;
      const decryptByte = (Math.imul(temp, (temp ^ 1)) >> 8) & 255;
      const C = (decryptByte ^ data[i]) & 255;
      this.updateKeys(data[i]); // Difference is here
      output[i] = C;
    }
    return output;
  }
}

///////////////  CRC32  //////////////
function makeCRCTable() {
  let c;
  let crcTable = [];
  for (let i = 0; i < 256; i += 1) {
      c = i;
      for (let k = 0; k < 8; k += 1) {
          c = ((c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1));
      }
      crcTable[i] = c;
  }
  return crcTable;
}

function crc32Inverse(str, crc) {
  const crcTable = window.crcTable || (window.crcTable = makeCRCTable());
  if (crc === undefined) {
    crc = 0 ^ (-1);
  }
  
  crc = (crc >>> 8) ^ crcTable[(crc ^ str) & 0xFF];
  return crc >>> 0;
}

function crc32(str, crc) {
  return (~crc32Inverse(str, crc === undefined ? undefined : ~crc)) >>> 0;
};

function fileCrc32(fBuf, crc) {
  const crcTable = window.crcTable || (window.crcTable = makeCRCTable());
  if (crc === undefined) {
    crc = 0 ^ (-1);
  }
  
  for (let i = 0; i < fBuf.length; i += 1) {
    crc = (crc >>> 8) ^ crcTable[(crc ^ fBuf[i]) & 0xFF];
  }
  return (~crc) >>> 0;
}

function getInt32(number) {
	return number & 0xFFFFFFFF;
}

function decodeZipDateTime(time, date) {
  const second = (time & 31) * 2;
  const minute = (time & 2016) >> 5;
  const hour = (time & 63488) >> 11;

  const day = (date & 31);
  const month = (date & 480) >> 5;
  const year = ((date & 65024) >> 9) + 1980;
  return new Date(year, month - 1, day, hour, minute, second, 0);
}

function encodeZipDateTime(dateObj) {
  let time = Math.floor(dateObj.getSeconds() / 2) & 31;
  time += (dateObj.getMinutes() & 63) << 5;
  time += (dateObj.getHours() & 31) << 11;

  let date = (dateObj.getDate()) & 31;
  date += ((dateObj.getMonth() + 1) & 15) << 5;
  date += ((dateObj.getYear() - 80) & 127) << 9;

  return [date, time];
}
