// Lecture vidéo : fichier local, YouTube (yt:ID) ou Google Drive (drive:ID)
window.videoHTML = function (ref) {
  const e = (s) => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  if (/^yt:[A-Za-z0-9_-]{11}$/.test(ref)) return `<iframe src="https://www.youtube-nocookie.com/embed/${ref.slice(3)}?autoplay=1&rel=0&playsinline=1" allow="autoplay; encrypted-media; picture-in-picture" allowfullscreen style="width:min(92vw,420px);aspect-ratio:9/16;max-height:78vh;border:0;border-radius:16px;background:#000"></iframe>`;
  if (/^drive:[A-Za-z0-9_-]+$/.test(ref)) return `<iframe src="https://drive.google.com/file/d/${ref.slice(6)}/preview" allow="autoplay" allowfullscreen style="width:min(92vw,420px);aspect-ratio:9/16;max-height:78vh;border:0;border-radius:16px;background:#000"></iframe>`;
  return `<video src="${e(ref)}" controls autoplay playsinline></video>`;
};
window.openVideo = function (ref) {
  const x = document.createElement('div'); x.className = 'vid-bg';
  x.innerHTML = window.videoHTML(ref) + '<button>Fermer</button>';
  x.querySelector('button').onclick = () => x.remove(); document.body.appendChild(x);
};
