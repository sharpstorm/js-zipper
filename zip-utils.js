var readShort, readInt, readLong, readString, readByteArray, writeShort, writeInt, writeLong, writeString, hasUtf8, arrToString; //Bit Tools

var META_LENGTH = 8;
var CHUNK_SIZE = 5 * 1024 * 1024; //5mb

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

class Archive{
  constructor(ft, file){
    this.fileTable = ft;
    this.file = file;
    if(this.fileTable == undefined){
      this.fileTable = new CentralDirectory();
    }
  }

  export(encrypted, encryptMode, password){
    if(encrypted === undefined){
      encrypted = false;
    }
    if(encrypted === true && (encryptMode === undefined || encryptMode < 0 || encryptMode > 1 || password === undefined || password === '')){
      encrypted = false;
    }

    return new Promise(async (resolve) => {
      const centralDir = this.fileTable;
      centralDir.fillFromDirectoryTree();

      const exportContents = [];
      let positionPointers = [];
      let curPosition = 0;

      for(let i=0;i<centralDir.fileRecords.length;i++){
        const curRecord = centralDir.fileRecords[i];
        if(curRecord.localFileHeader === undefined) continue;

        //Files, perform compression
        if(!curRecord.localFileHeader.isCompressed){
          curRecord.localFileHeader.dataBlob = pako.deflateRaw(curRecord.localFileHeader.dataBlob);
          curRecord.localFileHeader.isCompressed = true;
          curRecord.localFileHeader.compressionMethod = COMPRESSION_METHOD.DEFLATE;
          curRecord.localFileHeader.compressedSize = curRecord.localFileHeader.dataBlob.length;

          curRecord.compressionMethod = COMPRESSION_METHOD.DEFLATE;
          curRecord.compressedSize = curRecord.localFileHeader.dataBlob.length;
        }

        //Write position to tracking array
        positionPointers.push(curPosition);

        //Write local file header to target
        let binLocalHeader;
        if(encrypted){
          console.log("writing encrypted header " + encryptMode);
          binLocalHeader = curRecord.localFileHeader.writeEncryptedHeader(encryptMode);
          CentralDirectory.copyRecord(curRecord, curRecord.localFileHeader);
        }else{
          binLocalHeader = curRecord.localFileHeader.writeHeader();
        }
        
        curPosition += binLocalHeader.length;
        exportContents.push(binLocalHeader);
        
        //Write file to target
        if(encrypted){
          if(encryptMode === ENCRYPT_MODE.AES){
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

          }else if(encryptMode === ENCRYPT_MODE.ZIPCRYPTO){
            //Init the 3 crypt keys
            let key0 = 305419896;
            let key1 = 591751049;
            let key2 = 878082192;

            const updateKeys = (char) => {
              key0 = crc32(char, key0);
              key1 = unsignInt(key1 + (key0 & 255));
              key1 = unsignInt(safeMultiply(unsignInt(key1), 134775813) + 1);
              key2 = crc32(((key1 >> 24) & 255), key2);
            }

            for(let i=0;i<password.length;i++){
              updateKeys(password[i]);
            }

            //Write Stream Initialiser
            //let initBytes = new Uint8Array(12);
            //window.crypto.getRandomValues(initBytes);
            let initBytes = new Uint8Array([223, 109, 96, 78, 18, 65, 151, 57, 226, 189, 51, 0])
            initBytes[11] = (curRecord.localFileHeader.crc32 >> 24) & 255;
            console.log(initBytes);

            for(let i=0;i<12;i++){
              let temp = ((key2 & 65535) | 2) & 65535;
              let decryptByte = (((temp * (temp ^ 1)) & 65535) >> 8) & 255;
              updateKeys(initBytes[i]);

              let C = (initBytes[i] ^ decryptByte) & 255;
              initBytes[i] = C;
            }
            exportContents.push(initBytes);

            let encryptedContents = new Uint8Array(curRecord.localFileHeader.dataBlob.length);
            for(let i=0;i<curRecord.localFileHeader.dataBlob.length;i++){
              let temp = ((key2 & 65535) | 2) & 65535;
              let decryptByte = (((temp * (temp ^ 1)) & 65535) >> 8) & 255;
              updateKeys(curRecord.localFileHeader.dataBlob[i]);
              let C = (curRecord.localFileHeader.dataBlob[i] ^ decryptByte) & 255;
              encryptedContents[i] = C;
            }
            exportContents.push(encryptedContents);

            curPosition += curRecord.localFileHeader.dataBlob.length + 12;
          }
          
        }else{
          exportContents.push(curRecord.localFileHeader.dataBlob);
          curPosition += curRecord.localFileHeader.dataBlob.length;
        }
        
      }

      // Write Central Directory
      let centralDirSize = 0;
      for(let i=0;i<centralDir.fileRecords.length;i++){
        const recordBinary = centralDir.fileRecords[i].writeRecord(positionPointers[i]);
        exportContents.push(recordBinary);
        centralDirSize += recordBinary.length;
      }

      //Write end of centralDirectory
      exportContents.push(centralDir.exportEndOfCentralDirectory(centralDirSize, curPosition));

      resolve(new Blob(exportContents, {type: 'application/zip'}))
    });
  }

  static from(file){
    return new Promise((resolve, reject) => {
      this.scanForCentralDirectory(file)
      .then((archive) => {
        archive.fileTable.parseLocalFileHeaders()
        .then(() => {
          archive.fileTable.resolveDirectoryTree();
          resolve(archive);
        })
        .catch(reason => reject(reason));
      })
      .catch(reason => reject(reason));
    });
  }

  static scanForCentralDirectory(file){
    return new Promise((resolve, reject) => {
      //Start from back of file
      let CHUNK_SIZE = 65536;
      let end = file.size;
      const worker = () => {
        const start = (end-CHUNK_SIZE >= 0) ? end-CHUNK_SIZE : 0;
        readFile(file, start, end)
        .then(result => new Uint8Array(result))
        .then((result) => {
          const dirIdx = searchByteArray(result, END_OF_CENTRAL_DIRECTORY_SIG);

          if(dirIdx >= 0){
            readFile(file, start + dirIdx, start + dirIdx + 20)
            .then(result => new Uint8Array(result))
            .then(result => {
              const size = readInt(result, 12);
              const offset = readInt(result, 16);
              console.log(size, offset);

              CentralDirectory.from(file, offset, size)
              .then((cd) => {
                if(cd === undefined){
                  reject('Failed to parse central directory');
                  return;
                }

                resolve(new Archive(cd, file));
              })
              .catch(() => {
                reject('Failed to parse central directory');
                return;
              });
            });
            return;
          }

          //Not Found
          end -= CHUNK_SIZE - 4; //Overlap
          if(end < 0) {
            reject('Central Directory Not Found');
            return;
          }

          worker();
        });
      }
      worker();
    });
  }
}

class CentralDirectory{
  constructor(file){
    this.file = file;
    this.fileRecords = [];
    this.fileTree = {};
  }

  parseLocalFileHeaders(){
    let promises = [];
    for(let i=0;i<this.fileRecords.length;i++){
      promises.push(this.fileRecords[i].parseLocalFileHeader());
    }
    return Promise.all(promises);
  }

  resolveDirectoryTree(){
    for(let i=0;i<this.fileRecords.length;i++){
      let pathParts = this.fileRecords[i].fileName.split('/');
      let curFolder = this.fileTree;
      for(let j=0;j<pathParts.length;j++){
        if(j === pathParts.length - 1){ //final item
          if(pathParts[j] === '') continue;

          curFolder[pathParts[j]] = this.fileRecords[i].localFileHeader;
        }else{
          if(!(pathParts[j] in curFolder)){
            curFolder[pathParts[j]] = {};
          }
          curFolder = curFolder[pathParts[j]];
        }
      }
    }
  }

  //Takes the directory tree data and fills in the individual records
  fillFromDirectoryTree(){
    this.fileRecords = [];
    this.fillTreeNode(this.fileTree, '');
  }

  fillTreeNode(node, curPath){
    if(curPath !== ''){
      const curPathRecord = new CentralFileRecord();
      curPathRecord.fileName = curPath;
      this.fileRecords.push(curPathRecord);
    }

    const keys = Object.keys(node);
    for(let i=0;i<keys.length;i++){
      if(node[keys[i]] instanceof File){
        const fRecord = new CentralFileRecord();
        fRecord.fileName = curPath + keys[i];
        fRecord.lastModified = node[keys[i]].lastModified;
        fRecord.uncompressedSize = node[keys[i]].uncompressedSize;
        fRecord.crc32 = node[keys[i]].crc32;
        fRecord.localFileHeader = node[keys[i]];
        this.fileRecords.push(fRecord);
      }else{
        this.fillTreeNode(node[keys[i]], curPath + keys[i] + '/');
      }
    }
  }

  exportEndOfCentralDirectory(size, offset){
    let ret = [];
    for(let i=0;i<END_OF_CENTRAL_DIRECTORY_SIG.length;i++){
      ret.push(END_OF_CENTRAL_DIRECTORY_SIG[i]);
    }

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

  static copyRecord(centralRecord, localRecord){
    centralRecord.flags = localRecord.flags;
    centralRecord.lastModified = localRecord.lastModified;
    centralRecord.uncompressedSize = localRecord.uncompressedSize;
    centralRecord.compressedSize = localRecord.compressedSize;
    centralRecord.crc32 = localRecord.crc32;
  }

  static from(file, offset, size){
    return new Promise((resolve, reject) => {
      readFile(file, offset, offset + size)
      .then(result => new Uint8Array(result))
      .then(result => {
        const centralDirectory = new CentralDirectory(file);

        //Read as per records
        for(let i=0;i<size;i++){
          //validate sig
          let isValid = true;
          for(let j = 0; j < CENTRAL_DIRECTORY_SIG.length; j++){
            if(result[i + j] !== CENTRAL_DIRECTORY_SIG[j]) {
              isValid = false;
              break;
            }
          }
          if(!isValid) continue;

          const centralFile = new CentralFileRecord(centralDirectory);

          const ver = readShort(result, i + 4);
          const minVer = readShort(result, i + 6);
          centralFile.flags = readShort(result, i + 8);
          centralFile.compressionMethod = readShort(result, i + 10);
          const lastModTime = readShort(result, i + 12);
          const lastModDate = readShort(result, i + 14);
          centralFile.lastModified = decodeZipDateTime(lastModTime, lastModDate);
          centralFile.crc32 = readInt(result, i + 16);
          centralFile.compressedSize = readInt(result, i + 20);
          centralFile.uncompressedSize = readInt(result, i + 24);
          const fileNameLen = readShort(result, i + 28);
          const extraLen = readShort(result, i + 30);
          const commentLen = readShort(result, i + 32);
          const startDisk = readShort(result, i + 34); //Ignore
          centralFile.internalFileAttributes = readShort(result, i + 36);
          centralFile.externalFileAttributes = readInt(result, i + 38);
          centralFile.fileOffset = readInt(result, i + 42);

          if((centralFile.flags & GP_FLAG.IS_UTF8) == GP_FLAG.IS_UTF8){
            centralFile.fileName = decodeEncodedString(result, i + 46, true, i + 46 + fileNameLen);
          }else{
            centralFile.fileName = decodeEncodedString(result, i + 46, false, i + 46 + fileNameLen);
          }
          
          centralFile.extra = decodeEncodedString(result, i + 46 + fileNameLen, false, i + 46 + fileNameLen + extraLen);
          centralFile.comment = decodeEncodedString(result, i + 46 + fileNameLen + extraLen, false, i + 46 + fileNameLen + extraLen + commentLen);

          centralDirectory.fileRecords.push(centralFile);

          i += 45 + fileNameLen + extraLen + commentLen; //-1 because the loop will do a +1
        }
        console.log("Read " + centralDirectory.fileRecords.length + " files");
        resolve(centralDirectory);
      });
    });
  }
}

class CentralFileRecord{
  constructor(centralDirectory){
    this.centralDirectory = centralDirectory;

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

  parseLocalFileHeader(){
    return new Promise(resolve => {
      if(this.fileOffset < 0) resolve();

      File.readHeader(this.centralDirectory.file, this.fileOffset)
      .then(result => {
        this.localFileHeader = result;
        resolve();
      });
    });
  }

  writeRecord(offset){
    let ret = [];

    for(let i=0;i<CENTRAL_DIRECTORY_SIG.length;i++){
      ret.push(CENTRAL_DIRECTORY_SIG[i]);
    }

    const dateTime = encodeZipDateTime(this.lastModified);
    let fNameEncoded;
    if(hasUtf8(this.fileName)){
      fNameEncoded = encodeString(this.fileName, true);
      this.flags |= GP_FLAG.IS_UTF8;
    }else{
      fNameEncoded = encodeString(this.fileName);
      if(this.flags & GP_FLAG.IS_UTF8 === GP_FLAG.IS_UTF8){
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
}

class File{
  constructor(file){
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

  isAESEncrypted(){
    return this.compressionMethod === 99 && this.flags & GP_FLAG.ENCRYPTED_FILE === GP_FLAG.ENCRYPTED_FILE;
  }

  isZipCryptoEncrypted(){
    return this.flags & GP_FLAG.ENCRYPTED_FILE === GP_FLAG.ENCRYPTED_FILE;
  }

  isEncrypted(){
    return this.isAESEncrypted() || this.isZipCryptoEncrypted();
  }

  extract(password){
    if(this.isCached)
      return this.extractCached();
    
    if(this.isAESEncrypted())
      return this.extractAES(password);
    else if(this.isZipCryptoEncrypted())
      return this.extractZipCrypto(password);
    else
      return this.extractUnprotected();
  }

  extractUnprotected(){
    return readFile(this.file, this.dataOffset, this.dataOffset + this.compressedSize)
      .then(result => new Uint8Array(result))
      .then(result => {
        if(this.compressionMethod === COMPRESSION_METHOD.DEFLATE){
          return pako.inflateRaw(result);
        }
      });
  }

  extractZipCrypto(password){
    return new Promise((resolve, reject) => {
      //Init the 3 crypt keys
      let key0 = 305419896;
      let key1 = 591751049;
      let key2 = 878082192;

      const updateKeys = (char) => {
        key0 = crc32(char, key0);
        key1 = unsignInt(key1 + (key0 & 255));
        key1 = unsignInt(safeMultiply(unsignInt(key1), 134775813) + 1);
        key2 = crc32(((key1 >> 24) & 255), key2);
      }

      for(let i=0;i<password.length;i++){
        updateKeys(password[i]);
      }

      readFile(this.file, this.dataOffset, this.dataOffset + 12)
      .then(result => new Uint8Array(result))
      .then(result => {
        let decryptedBuffer = [0,0,0,0,0,0,0,0,0,0,0,0];
        for(let i=0;i<12;i++){
          let temp = ((key2 & 65535) | 2) & 65535;
          let decryptByte = (((temp * (temp ^ 1)) & 65535) >> 8) & 255;
          let C = (result[i] ^ decryptByte) & 255;
          updateKeys(C);
          decryptedBuffer[i] = C;
        }
        console.log(decryptedBuffer);
        if(decryptedBuffer[11] !== ((this.crc32 >> 24)&255)){
          reject('Incorrect password');
          return;
        }
        
        readFile(this.file, this.dataOffset + 12, this.dataOffset + this.compressedSize)
          .then(result => new Uint8Array(result))
          .then(result => {
            for(let i=0;i<result.length;i++){
              let temp = ((key2 & 65535) | 2) & 65535;
              let decryptByte = (((temp * (temp ^ 1)) & 65535) >> 8) & 255;
              let C = (result[i] ^ decryptByte) & 255;
              updateKeys(C);
              result[i] = C;
            }
            if(this.compressionMethod === COMPRESSION_METHOD.DEFLATE){
              let uncompressed;
              try{
                uncompressed = pako.inflateRaw(result);
              }catch(err){
                console.log(err);
              }
              resolve(uncompressed);
            }
          });
      });
    })
    
  }

  extractAES(password){
    return new Promise((resolve, reject) => {
      //read extra field
      let isValid = true;
      for(let j = 0; j < AES_EXTRA_SIG.length; j++){
        if(this.extra[j] !== AES_EXTRA_SIG[j]) {
          isValid = false;
          break;
        }
      }
      if(!isValid){
        reject('Invalid AES Extra Signature');
        return;
      }

      const AESExtraLen = readShort(this.extra, 2);
      if(AESExtraLen !== 7){
        reject('Invalid AES Extra Length');
        return;
      }

      const aesVer = readShort(this.extra, 4);
      const vendorId = readShort(this.extra, 6);
      const AESStrength = this.extra[8];
      const compressionMethod = readShort(this.extra, 9);

      const saltLen = AESSaltLength[AESStrength];
      const encryptedCompressedFileSize = this.compressedSize - saltLen - 12; //Encryption performed on compresed data, 12 = 2(Verify) + 10(Tail Auth Code)

      readFile(this.file, this.dataOffset, this.dataOffset + saltLen + 2)
      .then(result => new Uint8Array(result))
      .then(result => {
        const salt = result.slice(0, saltLen);
        const verifyCheck = result.slice(saltLen);
        
        pbkdf2('SHA-1', salt, password, 1000, 66)
        .then(result => new Uint8Array(result))
        .then(result2 => {
          if(verifyCheck[0] !== result2[64] || verifyCheck[1] !== result2[65]){
            console.log(salt, result2[64], result2[65], verifyCheck[0], verifyCheck[1]);
            reject('Invalid Password');
          }else{
            readFile(this.file, this.dataOffset + saltLen + 2, this.dataOffset + saltLen + 2 + encryptedCompressedFileSize)
            .then(result => new Uint8Array(result))
            .then(result => {
              console.log(result2.slice(0, AESKeyLength[AESStrength]));
              AESDecrypt(result, result2.slice(0, AESKeyLength[AESStrength])).then(plain => {
                console.log(plain.length);
                if(compressionMethod === COMPRESSION_METHOD.DEFLATE){
                  let uncompressed;
                  try{
                    uncompressed = pako.inflateRaw(plain);
                  }catch(err){
                    console.log(err);
                  }
                  resolve(uncompressed);
                }else{
                  resolve(plain);
                }
              });
            });
          }
        });
      })
    });
  }

  extractCached(){
    if(this.isCompressed){
      return new Promise(resolve => {
        resolve(pako.inflateRaw(this.dataBlob));
      });
    }else{
      return new Promise(resolve => resolve(this.dataBlob));
    }
  }

  writeHeader(){
    let ret = [];
    for(let i=0;i<LOCAL_FILE_HEADER_SIG.length;i++){
      ret.push(LOCAL_FILE_HEADER_SIG[i]);
    }
    const dateTime = encodeZipDateTime(this.lastModified);
    let fNameEncoded;
    if(hasUtf8(this.fileName)){
      fNameEncoded = encodeString(this.fileName, true);
      this.flags |= GP_FLAG.IS_UTF8;
    }else{
      fNameEncoded = encodeString(this.fileName);
      if((this.flags & GP_FLAG.IS_UTF8) === GP_FLAG.IS_UTF8){
        this.flags -= GP_FLAG.IS_UTF8;
      }
    }
    let extraLen = (this.extra === undefined) ? 0 : this.extra.length;
    
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

    if(this.extra !== undefined){
      ret = ret.concat(Array.from(this.extra));
    }

    return new Uint8Array(ret);
  }

  writeEncryptedHeader(encryptMode){
    if((this.flags & GP_FLAG.ENCRYPTED_FILE) !== GP_FLAG.ENCRYPTED_FILE){
      this.flags += GP_FLAG.ENCRYPTED_FILE;
      if(encryptMode === ENCRYPT_MODE.AES && this.compressionMethod !== 99){
        let trueCompressionMethod = this.compressionMethod;
        this.compressionMethod = 99;
        this.crc32 = 0;
        this.compressedSize += AESSaltLength[AES_STRENGTH.AES256] + 12;
        //Build Extra
        let extra = [];
        for(let i=0;i<AES_EXTRA_SIG.length;i++){
          extra.push(AES_EXTRA_SIG[i]);
        }
        extra = extra.concat(
          writeShort(7), // AES Length
          writeShort(2), // AES Version
          writeShort(17729), // Vendor ID
          [AES_STRENGTH.AES256],
          writeShort(trueCompressionMethod)
        );
        this.extra = new Uint8Array(extra);
      }else if(encryptMode === ENCRYPT_MODE.ZIPCRYPTO){
        this.compressedSize += 12;
      }
    }
    return this.writeHeader();
  }

  static readHeader(file, offset){
    return new Promise((resolve, reject) => {
      readFile(file, offset, offset + 30)
      .then(result => new Uint8Array(result))
      .then(result => {
        const localFileHeader = new File();
        localFileHeader.file = file;

        //validate sig
        let isValid = true;
        for(let j = 0; j < LOCAL_FILE_HEADER_SIG.length; j++){
          if(result[j] !== LOCAL_FILE_HEADER_SIG[j]) {
            isValid = false;
            break;
          }
        }
        if(!isValid){
          reject();
          return;
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

        readFile(file, offset + 30, offset + 30 + fNameLen + extraLen)
        .then(result => new Uint8Array(result))
        .then(result => {
          localFileHeader.fileName = decodeEncodedString(result, 0, localFileHeader.flags & GP_FLAG.IS_UTF8 === GP_FLAG.IS_UTF8, fNameLen);
          localFileHeader.extra = readByteArray(result, fNameLen, fNameLen + extraLen);
          localFileHeader.dataOffset = offset + 30 + fNameLen + extraLen;
          resolve(localFileHeader);
        });
      });
    });
  }

  static fromUpload(file){
    return new Promise((resolve, reject) => {
      readFile(file, 0, file.size)
        .then(result => new Uint8Array(result))
        .then(result => {
          const ret = new File();
          ret.dataBlob = result;
          ret.isCached = true;
          ret.uncompressedSize = file.size;
          ret.fileName = file.name;
          ret.crc32 = fileCrc32(result);
          ret.lastModified = file.lastModifiedDate

          resolve(ret);
        });
    });
  }
}

function initFileReader(){
  if(fileReader == undefined){
    fileReader = new FileReader();
  }
}

const readQueue = [];
let readBusy = false;

function readFile(file, start, end) {
  if(readBusy){
    return new Promise((resolve) => {
      readQueue.push([file, start, end, resolve]);
    });
  }

  //Is free
  initFileReader();
  return new Promise((resolve) => {
    readBusy = true;
    fileReader.onloadend = function(){
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

function makeCRCTable(){
  let c;
  let crcTable = [];
  for(let n = 0; n < 256; n++){
      c = n;
      for(let k = 0; k < 8; k++){
          c = ((c&1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1));
      }
      crcTable[n] = unsignInt(c);
  }
  return crcTable;
}

var crc32 = function(str, crc) {
  var crcTable = window.crcTable || (window.crcTable = makeCRCTable());
  if(crc === undefined)
    crc = 0 ^ (-1);

  if(typeof(str) === 'string'){
    for (var i = 0; i < str.length; i++ ) {
        crc = ((crc >> 8) & 16777215) ^ crcTable[(crc & 255) ^ str.charCodeAt(i)];
    }
  }else if(typeof(str) === 'number'){
    crc = ((crc >> 8) & 16777215) ^ crcTable[(crc & 255) ^ str];
  }

  return unsignInt(crc);
};

function fileCrc32(fBuf, crc){
  var crcTable = window.crcTable || (window.crcTable = makeCRCTable());
  if(crc === undefined)
    crc = 0 ^ (-1);
  for (var i = 0; i < fBuf.length; i++ ) {
    crc = (crc >>> 8) ^ crcTable[(crc & 255) ^ fBuf[i]];
  }
  crc = (crc ^ (-1)) >>> 0;
  return crc;
}

function unsignInt(inp){
  if(inp < 0){
    return (inp & 2147483647) + 2147483648;
  }
  if(inp > 2147483648 && ((inp >> 31) & 1 === 1)){
    return (inp & 2147483647) + 2147483648;
  }
  return inp & 2147483647;
}

function safeMultiply(a, b){ //Using Russian Peasant
  let res = 0;
  while(b > 0){
    if(b & 1)
      res = unsignInt(res + a);
    
    if((a & 0x10000000000000) === 0x10000000000000){
      a = a & 0xFFFFFFFFFFFFF;
    }
    a = a << 1;
    b = b >> 1;
    
    if(a > Number.MAX_SAFE_INTEGER) return res;
  }
  return res;
}

function decodeZipDateTime(time, date){
  const second = (time & 31) * 2;
  const minute = (time & 2016) >> 5;
  const hour = (time & 63488) >> 11;

  const day = (date & 31);
  const month = (date & 480) >> 5;
  const year = ((date & 65024) >> 9) + 1980;
  return new Date(year, month - 1, day, hour, minute, second, 0);
}

function encodeZipDateTime(dateObj){
  let time = Math.floor(dateObj.getSeconds() / 2) & 31;
  time += (dateObj.getMinutes() & 63) << 5;
  time += (dateObj.getHours() & 31) << 11;

  let date = (dateObj.getDate()) & 31;
  date += ((dateObj.getMonth() + 1) & 15) << 5;
  date += ((dateObj.getYear() - 80) & 127) << 9;

  return [date, time];
}