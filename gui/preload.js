const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
    startScan: (options) => ipcRenderer.send('start-scan', options),
    stopScan: () => ipcRenderer.send('stop-scan'),
    onProgress: (callback) => ipcRenderer.on('scan-progress', (event, data) => callback(data)),
    onThreat: (callback) => ipcRenderer.on('scan-threat', (event, data) => callback(data)),
    onCompleted: (callback) => ipcRenderer.on('scan-completed', (event, data) => callback(data)),

    // System Cleaner APIs
    scanJunkFiles: () => ipcRenderer.invoke('scan-junk-files'),
    cleanJunkFiles: (categories) => ipcRenderer.invoke('clean-junk-files', categories),

    // Remote Auto-Update APIs
    checkRemoteUpdate: () => ipcRenderer.invoke('check-remote-update'),
    downloadUpdate: () => ipcRenderer.invoke('download-update'),
    installUpdate: () => ipcRenderer.invoke('install-update'),
    onUpdateProgress: (callback) => ipcRenderer.on('update-download-progress', (event, data) => callback(data)),

    // Real-Time Downloads Guard APIs
    onDownloadScanStarted: (callback) => ipcRenderer.on('download-scan-started', (event, data) => callback(data)),
    onDownloadScanFinished: (callback) => ipcRenderer.on('download-scan-finished', (event, data) => callback(data)),
    onTriggerQuickScan: (callback) => ipcRenderer.on('trigger-quick-scan', () => callback())
});


