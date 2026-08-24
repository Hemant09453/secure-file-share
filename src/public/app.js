document.addEventListener('DOMContentLoaded', () => {
  let selectedFile = null;
  let downloadFileId = null;
  let currentShareId = null;
  let authToken = localStorage.getItem('sec_file_share_token') || '';

  // Auth Tab Switching
  const tabLoginBtn = document.getElementById('tab-login-btn');
  const tabSignupBtn = document.getElementById('tab-signup-btn');
  const loginForm = document.getElementById('login-form');
  const signupForm = document.getElementById('signup-form');

  tabLoginBtn.addEventListener('click', () => {
    tabLoginBtn.classList.add('active');
    tabSignupBtn.classList.remove('active');
    loginForm.style.display = 'flex';
    signupForm.style.display = 'none';
  });

  tabSignupBtn.addEventListener('click', () => {
    tabSignupBtn.classList.add('active');
    tabLoginBtn.classList.remove('active');
    signupForm.style.display = 'flex';
    loginForm.style.display = 'none';
  });

  checkAuthSession();

  async function checkAuthSession() {
    const hash = window.location.hash;
    if (hash.startsWith('#share/')) {
      const fileId = hash.replace('#share/', '');
      if (fileId) { showShareReceiverPortal(fileId); return; }
    }
    if (!authToken) { showAuthScreen(); return; }
    try {
      const res = await fetch('/api/auth/me', { headers: { 'Authorization': `Bearer ${authToken}` } });
      if (res.ok) {
        const data = await res.json();
        showAuthenticatedApp(data.user);
      } else {
        localStorage.removeItem('sec_file_share_token');
        authToken = '';
        showAuthScreen();
      }
    } catch (_) { showAuthScreen(); }
  }

  function showAuthScreen() {
    document.getElementById('auth-screen').style.display = 'flex';
    document.getElementById('standard-dashboard').style.display = 'none';
    document.getElementById('share-receiver-card').style.display = 'none';
    document.getElementById('user-header-chip').style.display = 'none';
  }

  function showAuthenticatedApp(user) {
    document.getElementById('auth-screen').style.display = 'none';
    document.getElementById('share-receiver-card').style.display = 'none';
    document.getElementById('standard-dashboard').style.display = 'block';
    document.getElementById('header-username').innerText = user.username;
    document.getElementById('user-header-chip').style.display = 'inline-flex';
    fetchFilesList();
  }

  loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('login-username').value;
    const password = document.getElementById('login-password').value;
    const btn = document.getElementById('login-btn');
    btn.disabled = true;
    btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Signing In...`;
    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      });
      const data = await res.json();
      if (data.success) {
        authToken = data.token;
        localStorage.setItem('sec_file_share_token', authToken);
        showAuthenticatedApp(data.user);
      } else {
        alert(`Sign In Failed: ${data.error}`);
      }
    } catch (err) {
      alert(`Network error: ${err.message}`);
    } finally {
      btn.disabled = false;
      btn.innerHTML = `<i class="fa-solid fa-right-to-bracket"></i> Sign In to Vault`;
    }
  });

  signupForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('signup-username').value;
    const email = document.getElementById('signup-email').value;
    const password = document.getElementById('signup-password').value;
    const btn = document.getElementById('signup-btn');
    btn.disabled = true;
    btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Creating Account...`;
    try {
      const res = await fetch('/api/auth/signup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, email, password })
      });
      const data = await res.json();
      if (data.success) {
        authToken = data.token;
        localStorage.setItem('sec_file_share_token', authToken);
        showAuthenticatedApp(data.user);
      } else {
        alert(`Registration Failed: ${data.error}`);
      }
    } catch (err) {
      alert(`Network error: ${err.message}`);
    } finally {
      btn.disabled = false;
      btn.innerHTML = `<i class="fa-solid fa-user-check"></i> Create Account & Sign In`;
    }
  });

  window.handleLogout = async () => {
    try {
      await fetch('/api/auth/logout', { method: 'POST', headers: { 'Authorization': `Bearer ${authToken}` } });
    } catch (_) {}
    localStorage.removeItem('sec_file_share_token');
    authToken = '';
    showAuthScreen();
  };

  async function showShareReceiverPortal(fileId) {
    currentShareId = fileId;
    document.getElementById('auth-screen').style.display = 'none';
    document.getElementById('standard-dashboard').style.display = 'none';
    document.getElementById('share-receiver-card').style.display = 'flex';
    try {
      const res = await fetch(`/api/share-info/${fileId}`);
      if (!res.ok) { alert('Share link invalid or expired.'); return; }
      const data = await res.json();
      document.getElementById('share-filename').innerText = data.originalName;
      document.getElementById('share-filesize').innerText = `${(data.size / 1024).toFixed(1)} KB`;
      document.getElementById('share-checksum').innerText = data.checksum.substring(0, 16) + '...';
    } catch (err) { console.error(err); }
  }

  document.getElementById('share-download-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const pwd = document.getElementById('share-decrypt-password').value;
    const btn = document.getElementById('share-decrypt-btn');
    btn.disabled = true;
    btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Decrypting...`;
    try {
      const res = await fetch(`/api/download/${currentShareId}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: pwd })
      });
      if (!res.ok) { const err = await res.json(); alert(`Access Denied: ${err.error}`); return; }
      const blob = await res.blob();
      const cd = res.headers.get('Content-Disposition');
      let filename = cd ? cd.split('filename=')[1].replace(/"/g, '') : 'decrypted-file';
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = filename;
      document.body.appendChild(a); a.click(); a.remove();
      alert('File successfully decrypted and downloaded!');
        // Hide share view and return to dashboard
        document.getElementById('share-receiver-card').style.display = 'none';
        document.getElementById('standard-dashboard').style.display = 'block';
        window.location.hash = '';
    } catch (err) { alert(`Decryption failed: ${err.message}`); }
    finally {
      btn.disabled = false;
      btn.innerHTML = `<i class="fa-solid fa-lock-open"></i> Decrypt & Download File`;
    }
  });

  // Drag & Drop
  const dropzone = document.getElementById('dropzone');
  const fileInput = document.getElementById('file-input');
  const filePreview = document.getElementById('file-preview');
  const previewName = document.getElementById('preview-name');

  fileInput.addEventListener('change', (e) => {
    if (e.target.files.length > 0) {
      selectedFile = e.target.files[0];
      previewName.innerText = `${selectedFile.name} (${(selectedFile.size / 1024).toFixed(1)} KB)`;
      filePreview.style.display = 'inline-flex';
    }
  });

  dropzone.addEventListener('dragover', (e) => { e.preventDefault(); dropzone.style.borderColor = 'var(--accent-cyan)'; });
  dropzone.addEventListener('dragleave', () => { dropzone.style.borderColor = 'rgba(0, 242, 254, 0.3)'; });
  dropzone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropzone.style.borderColor = 'rgba(0, 242, 254, 0.3)';
    if (e.dataTransfer.files.length > 0) {
      fileInput.files = e.dataTransfer.files;
      selectedFile = e.dataTransfer.files[0];
      previewName.innerText = `${selectedFile.name} (${(selectedFile.size / 1024).toFixed(1)} KB)`;
      filePreview.style.display = 'inline-flex';
    }
  });

  // File Upload & QR Generation
  document.getElementById('upload-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!selectedFile) { alert('Please select a file!'); return; }
    const password = document.getElementById('upload-password').value;
    if (!password) { alert('Please enter a decryption password!'); return; }
    const formData = new FormData();
    formData.append('file', selectedFile);
    formData.append('password', password);
    formData.append('expiryHours', document.getElementById('upload-expiry').value);
    const uploadBtn = document.getElementById('upload-btn');
    uploadBtn.disabled = true;
    uploadBtn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Encrypting & Uploading...`;
    try {
      const res = await fetch('/api/upload', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${authToken}` },
        body: formData
      });
      const data = await res.json();
      if (data.success) {
        const fullShareUrl = `${window.location.origin}/#share/${data.file.id}`;
        document.getElementById('share-link-input').value = fullShareUrl;
        renderQrCode(fullShareUrl, 'modal-qrcode-canvas', 'modal-qrcode-img');
        document.getElementById('share-modal').classList.add('active');
        document.getElementById('test-share-link-btn').onclick = () => {
          closeShareModal();
          window.location.hash = `#share/${data.file.id}`;
        };
        selectedFile = null;
        fileInput.value = '';
        filePreview.style.display = 'none';
        fetchFilesList();
      } else {
        alert(`Upload error: ${data.error}`);
      }
    } catch (err) { alert(`Upload failed: ${err.message}`); }
    finally {
      uploadBtn.disabled = false;
      uploadBtn.innerHTML = `<i class="fa-solid fa-lock"></i> Encrypt, Upload & Generate Link / QR`;
    }
  });

  function renderQrCode(url, canvasId, imgId) {
    const canvasDiv = document.getElementById(canvasId);
    const fallbackImg = document.getElementById(imgId);
    canvasDiv.innerHTML = '';
    if (typeof QRCode !== 'undefined') {
      try {
        new QRCode(canvasDiv, { text: url, width: 180, height: 180, colorDark: '#0b0f19', colorLight: '#ffffff', correctLevel: QRCode.CorrectLevel.H });
        fallbackImg.style.display = 'none';
        canvasDiv.style.display = 'inline-block';
        return;
      } catch (_) {}
    }
    fallbackImg.src = `https://api.qrserver.com/v1/create-qr-code/?size=180x180&data=${encodeURIComponent(url)}`;
    fallbackImg.style.display = 'inline-block';
    canvasDiv.style.display = 'none';
  }

  window.showQrModal = (id, filename) => {
    const link = `${window.location.origin}/#share/${id}`;
    document.getElementById('qr-modal-title').innerHTML = `<i class="fa-solid fa-qrcode"></i> Scan QR: ${escapeHtml(filename)}`;
    document.getElementById('qr-viewer-img').src = `https://api.qrserver.com/v1/create-qr-code/?size=220x220&data=${encodeURIComponent(link)}`;
    document.getElementById('qr-viewer-modal').classList.add('active');
  };

  window.closeQrViewerModal = () => document.getElementById('qr-viewer-modal').classList.remove('active');

  document.getElementById('copy-share-btn').addEventListener('click', () => {
    const input = document.getElementById('share-link-input');
    input.select();
    navigator.clipboard.writeText(input.value);
    alert('Shareable link copied!');
  });

  window.closeShareModal = () => document.getElementById('share-modal').classList.remove('active');

  async function fetchFilesList() {
    try {
      const res = await fetch('/api/files', { headers: { 'Authorization': `Bearer ${authToken}` } });
      if (!res.ok) return;
      const data = await res.json();
      const filesContainer = document.getElementById('files-list');
      if (!data.files || data.files.length === 0) {
        filesContainer.innerHTML = `<div class="empty-state"><i class="fa-solid fa-box-open"></i><p>No files uploaded yet. Upload a file to generate a password-protected share link and QR code!</p></div>`;
        return;
      }
      filesContainer.innerHTML = data.files.map(file => `
        <div class="file-item">
          <div class="file-info">
            <i class="fa-solid fa-file-shield file-icon"></i>
            <div class="file-details">
              <h4>${escapeHtml(file.originalName)}</h4>
              <div class="file-meta">
                <span>${(file.size / 1024).toFixed(1)} KB</span>
                <span>• ${escapeHtml(file.uploader || 'User')}</span>
                <span class="scan-tag"><i class="fa-solid fa-circle-check"></i> ${file.scanStatus === "not_scanned" ? "Not scanned" : file.scanStatus}</span>
              </div>
            </div>
          </div>
          <div class="file-actions">
            <button class="btn btn-sm btn-outline" onclick="showQrModal('${file.id}', '${escapeHtml(file.originalName)}')">
              <i class="fa-solid fa-qrcode"></i> QR
            </button>
            <button class="btn btn-sm btn-outline" onclick="copyFileShareLink('${file.id}')">
              <i class="fa-solid fa-link"></i> Copy Link
            </button>
            <button class="btn btn-sm btn-primary" onclick="initiateDownload('${file.id}', ${file.hasPassword})">
              <i class="fa-solid fa-download"></i> Decrypt
            </button>
            <button class="btn btn-sm btn-outline" onclick="deleteFile('${file.id}')">
              <i class="fa-solid fa-trash"></i>
            </button>
          </div>
        </div>`).join('');
    } catch (err) { console.error(err); }
  }

  window.copyFileShareLink = (id) => {
    const link = `${window.location.origin}/#share/${id}`;
    navigator.clipboard.writeText(link);
    alert(`Copied:\n${link}`);
  };

  window.initiateDownload = (id, hasPassword) => {
    downloadFileId = id;
    if (hasPassword) { document.getElementById('password-modal').classList.add('active'); }
    else { executeDownload(id, ''); }
  };

  window.closeModal = () => {
    document.getElementById('password-modal').classList.remove('active');
    document.getElementById('modal-password').value = '';
  };

  document.getElementById('confirm-download-btn').addEventListener('click', () => {
    const pwd = document.getElementById('modal-password').value;
    executeDownload(downloadFileId, pwd);
    closeModal();
  });

  async function executeDownload(id, password) {
    try {
      const res = await fetch(`/api/download/${id}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password })
      });
      if (!res.ok) { const err = await res.json(); alert(`Download Error: ${err.error}`); return; }
      const blob = await res.blob();
      const cd = res.headers.get('Content-Disposition');
      let filename = cd ? cd.split('filename=')[1].replace(/"/g, '') : 'decrypted-file';
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = filename;
      document.body.appendChild(a); a.click(); a.remove();
      fetchFilesList();
    } catch (err) { alert(`Download failed: ${err.message}`); }
  }

  window.deleteFile = async (id) => {
    if (!confirm('Delete this file from storage?')) return;
    try {
      const res = await fetch(`/api/files/${id}`, { method: 'DELETE', headers: { 'Authorization': `Bearer ${authToken}` } });
      const data = await res.json();
      if (data.success) fetchFilesList();
    } catch (err) { alert(`Delete failed: ${err.message}`); }
  };

  function escapeHtml(str) {
    return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  }

  document.getElementById('refresh-btn').addEventListener('click', fetchFilesList);
});
