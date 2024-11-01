const { app, BrowserWindow, Menu } = require('electron');
const { spawn } = require('child_process');
const path = require('path');

let mainWindow;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1224,
    height: 768,
    minWidth: 600,    // Set minimum width
    minHeight: 768,   // Set minimum height
    
    
    frame: true, // Remove the default window frame
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false,
    },
    icon: path.join(__dirname, 'assets', 'icon.ico') // Path to your icon file
    
  });

  mainWindow.loadURL('http://localhost:8501'); // Point to your Streamlit app

  // Customize window appearance (set a light color)
  mainWindow.setBackgroundColor('#ffffff'); // Change to your preferred light color

  // Optionally, remove the default menu
  Menu.setApplicationMenu(null);
}

app.on('ready', () => {
  const streamlitProcess = spawn('streamlit', ['run', 'SecureScribe.py']); 
// Replace with your app file

  streamlitProcess.stdout.on('data', (data) => {
    console.log(`${data}`);
  });

  streamlitProcess.stderr.on('data', (data) => {
    console.error(`${data}`);
  });

  createWindow();

  mainWindow.on('closed', () => {
    mainWindow = null;
    streamlitProcess.kill(); // Kill the Streamlit process when the window is closed
  });
});

app.on('window-all-closed', () => {
  app.quit();
});
