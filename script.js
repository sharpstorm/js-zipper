let curFile;
let fileReader;
let archive;
let curFolder;
let curFolderStack = [];

const icons = ['assets/folder.svg', 'assets/file.svg'];

document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('button-open').addEventListener('click', () => {
    document.getElementById('inp-archive-upload').click();
  });

  document.getElementById('button-create').addEventListener('click', () => {
    showBrowser();
    showCreateUtils();
    archive = new Archive();
    curFolder = archive.fileTable.fileTree;
    listFiles(curFolder);
  });

  document.getElementById('inp-archive-upload').addEventListener('change', archiveUploaded);
  document.getElementById('cb-has-password').addEventListener('change', () => {
    if(document.getElementById('cb-has-password').checked){
      document.getElementById('export-inner').classList.add('password-protected');
    }else{
      document.getElementById('export-inner').classList.remove('password-protected');
    }
  });

  attachEasterEgg();
});

function archiveUploaded(evt){
  const selectedFile = evt.target.files[0];
  if(selectedFile != undefined){
    curFile = selectedFile;
    document.getElementById('logo-path').style.strokeDasharray = 100;
    setTimeout(() => {
      document.getElementById('logo-path').style.animation = 'logo-loading 3s linear infinite alternate';

      Archive.from(curFile).then((result) => {
        if(result != undefined){
          archive = result;
          curFolder = archive.fileTable.fileTree;
          showBrowser();
          listFiles(curFolder);
        }else{
          //failed
          alert('Failed to parse as ZIP File');
        }
      })
      .catch(reason => {
        alert('Failed to parse as ZIP file. \nERR: ' + reason);
      });
    }, 2000);
  }else{
    curFile = undefined;
  }
}

function showBrowser(){
  document.getElementById('logo-path').style.strokeDasharray = 750;
  document.getElementById('page-browser').style.display = 'block';
  setTimeout(() => {
    document.getElementById('page-browser').style.clipPath = 'circle(200% at center)';
    setTimeout(() => {
      document.getElementById('page-browser').style.position = 'relative';
      document.getElementById('page-browser').style.top = '0px';
      document.getElementById('page-main').style.display = 'none';
    }, 2000);
  }, 100);
}

function showCreateUtils(){
  document.getElementById('browser-content').classList.add('editor');

  document.getElementById('btn-new-folder').onclick = () => {
    const fName = prompt('Enter Folder Name');
    if(fName === undefined) return;

    curFolder[fName] = {};
    listFiles(curFolder);
  };

  document.getElementById('btn-add-file').onclick = () => {
    document.getElementById('inp-add-file').click();
  };

  document.getElementById('inp-add-file').addEventListener('change', (evt) => {
    for(let i=0;i<evt.target.files.length;i++){
      const selectedFile = evt.target.files[i];
      if(selectedFile !== undefined){
        File.fromUpload(selectedFile)
          .then((f) => {
            curFolder[selectedFile.name] = f;
            listFiles(curFolder);
          });
      }
    }
  });

  document.getElementById('btn-export').addEventListener('click', () => {
    /*archive.export()
      .then((blob) => {
        const exportUrl = URL.createObjectURL(blob);
        document.getElementById('lnk-download-export').href = exportUrl;
        document.getElementById('lnk-download-export').click();
      });*/

    document.getElementById('export-overlay').classList.add('active');
    setTimeout(() => {
      document.getElementById('export-overlay').style.clipPath = 'circle(100% at center)';
      document.getElementById('btn-export-cancel').onclick = () => {
        document.getElementById('export-overlay').style.clipPath = 'circle(0% at center)';
        setTimeout(() => {
          document.getElementById('export-overlay').classList.remove('active');
        }, 1000);
      };

      document.getElementById('btn-export-confirm').onclick = () => {
        let passwordProtected = document.getElementById('cb-has-password').checked;
        if(passwordProtected){
          let encryptMode = document.getElementById('dl-encrypt-mode').selectedIndex;
          let password = document.getElementById('tb-encrypt-password').value;
          if(password === undefined || password === null || password === ''){
            alert('Password cannot be empty');
            return;
          }

          showLoading(() => {
            document.getElementById('export-overlay').style.clipPath = 'circle(0% at center)';
            setTimeout(() => {
              document.getElementById('export-overlay').classList.remove('active');
              archive.export(true, encryptMode, password)
              .then((blob) => {
                const exportUrl = URL.createObjectURL(blob);
                document.getElementById('lnk-download-export').href = exportUrl;
                document.getElementById('lnk-download-export').click();
                hideLoading();
              });
            }, 1000);
          });
        }else{
          showLoading(() => {
            document.getElementById('export-overlay').style.clipPath = 'circle(0% at center)';
            setTimeout(() => {
              document.getElementById('export-overlay').classList.remove('active');
              archive.export()
              .then((blob) => {
                const exportUrl = URL.createObjectURL(blob);
                document.getElementById('lnk-download-export').href = exportUrl;
                document.getElementById('lnk-download-export').click();
                hideLoading();
              });
            }, 1000);
          });
        }
      };
    }, 100);
  });
}

function clearFiles(){
  var c = document.getElementById('browser-path');
  while(c.lastChild) c.removeChild(c.lastChild);
  var x = document.getElementById('browser-list');
  while(x.lastChild) x.removeChild(x.lastChild);
}

function listFiles(folder){
  clearFiles();

  populatePath();

  const k = Object.keys(folder);
  const container = document.getElementById('browser-list');

  for(let i=0;i<k.length;i++){
    let iconSrc = (folder[k[i]] instanceof File) ? icons[1] : icons[0];
    let fileSize = (folder[k[i]] instanceof File) ? formatReadableSize(folder[k[i]].uncompressedSize) : '';

    const row = createElement('li', {attributes: {'data-name': k[i]}, onclick: openNode}, 
      createElement('img', {src: iconSrc}),
      createElement('div', {onclick: openNode}, k[i]),
      createElement('small', {}, fileSize)
    );
    
    container.appendChild(row);
  }
}

function populatePath(){
  const container = document.getElementById('browser-path');
  //Add Root
  container.appendChild(createElement('li', {
    eventListener: {
      'click': () => {
        curFolderStack = [];
        curFolder = archive.fileTable.fileTree;
        listFiles(curFolder);
      }
    },
    className: (curFolderStack.length === 0) ? 'active' : ''
  }, '/'));

  for(let i=0;i<curFolderStack.length;i++){
    let part = createElement('li', {}, curFolderStack[i][0]);
    if(i == curFolderStack.length - 1){
      part.classList.add('active');
    }else{
      const stackPosition = i;
      part.addEventListener('click', () => {
        for(let j=curFolderStack.length - 1;j>stackPosition;j--){
          curFolderStack.pop();
        }
        curFolder = curFolderStack[stackPosition][1];
        listFiles(curFolder);
      });
    }
    container.appendChild(part);
  }
}

function openNode(evt){
  evt.stopPropagation();
  const name = this.parentElement.getAttribute("data-name");
  if(name in curFolder){
    if(curFolder[name] instanceof File){
      let extractPromise;
      let pwd = undefined;
      if(curFolder[name].isEncrypted()){
        pwd = prompt('Enter Password for file');
        if(pwd === null)
          return;
      }
      showLoading(() => {
        extractPromise = curFolder[name].extract(pwd);
        extractPromise.then(result => {
          const url = URL.createObjectURL(new Blob([result], {type: 'octet/stream'}));
          const link = document.createElement('a');
          link.href = url;
          link.download = name;
          document.body.appendChild(link);
          link.click();
          document.body.removeChild(link);
          hideLoading();
        }).catch(err => {
          console.log(err);
          alert('Could not extract file: ' + err);
        });
      });
      
    }else{
      curFolder = curFolder[name];
      curFolderStack.push([name, curFolder]);
      listFiles(curFolder);
    }
  }
}

function showLoading(callback){
  document.getElementById('loading-overlay').classList.add('active');
  document.getElementById('loading-path').classList.add('active');
  setTimeout(() => {
    document.getElementById('loading-overlay').style.clipPath = 'circle(100% at center)';
    if(callback !== undefined)
      callback();
  }, 50);
}

function hideLoading(callback){
  document.getElementById('loading-overlay').style.clipPath = 'circle(0% at center)';
  setTimeout(() => {
    document.getElementById('loading-overlay').classList.remove('active');
    document.getElementById('loading-path').classList.remove('active');
    if(callback !== undefined)
      callback();
  }, 1000);
}

function attachEasterEgg(){
  //Easter egg
  const seq = [38,38,40,40,37,39,37,39,66,65];
  let curIdx = 0;
  document.addEventListener('keydown', (e) => {
      e = e || window.event;
      if(e.keyCode === seq[curIdx]){
        curIdx += 1;
      }else{
        curIdx = 0;
      }

      if(curIdx === seq.length){
        //activate
        document.getElementById('logo-path').style.animation = 'logo-rainbow 3s linear infinite';
        curIdx = 0;
      }
  });
}

//////////////////////// Helper Functions /////////////////////////

function createElement(type, attributes){
  var e = document.createElement(type);
  
  var k = Object.keys(attributes);
  for(var i=0;i<k.length;i++){
    if(typeof attributes[k[i]] == 'object'){
      var k2 = Object.keys(attributes[k[i]]);
      for(var j=0;j<k2.length;j++){
        if(k[i] === 'attributes'){
          e.setAttribute(k2[j], attributes[k[i]][k2[j]]);
        }else if(k[i] === 'eventListener'){
          e.addEventListener(k2[j], attributes[k[i]][k2[j]]);
        }else{
          e[k[i]][k2[j]] = attributes[k[i]][k2[j]];
        }
      }
    }else{
      e[k[i]] = attributes[k[i]];
    }
  }
  
  if(arguments.length > 2){
    for(var i=2;i<arguments.length;i++){
      if(arguments[i] == null || arguments[i] == undefined) continue;
      if(typeof arguments[i] === "string"){
        e.textContent = arguments[i];
      }else{
        e.appendChild(arguments[i]);
      }
    }
  }
  return e;
}

function formatReadableSize(size){
  if(size < 1024)
    return size + ' bytes';
  else if(size < 1024 * 1024)
    return Math.round(size / 1024) + ' kB';
  else if(size < 1024 * 1024 * 1024)
    return Math.round((size / 1024 / 1024) * 100) / 100 + ' MB';
  else if(size < 1024 * 1024 * 1024 * 1024)
    return Math.round((size / 1024 / 1024 / 1024) * 100) / 100 + ' GB';
  else if(size < 1024 * 1024 * 1024 * 1024 * 1024)
    return Math.round((size / 1024 / 1024 / 1024 / 1024) * 100) / 100 + ' TB';
}