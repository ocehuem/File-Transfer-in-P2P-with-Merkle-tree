function generatePeers() {
  const count = parseInt(document.getElementById("peerCount").value);
  const container = document.getElementById("peerContainer");
  container.innerHTML = "";

  for (let i = 1; i <= count; i++) {
    const peer = document.createElement("div");
    peer.className = "peer";
    peer.id = `peer-${i}`;
    peer.dataset.online = "false";

    peer.innerHTML = `
      <div><strong>P${i}</strong></div>
      <div class="buttons" style="display: none;">
        <button onclick="askFiles(${i})">Ask for Files</button>
        <button onclick="shareFiles(${i})">Share Files</button>
      </div>
    `;

    peer.addEventListener("click", function(e) {
      if (e.target.tagName === 'BUTTON') return; // ignore button clicks
      const online = peer.dataset.online === "true";
      peer.dataset.online = (!online).toString();
      peer.classList.toggle("online", !online);
      const buttons = peer.querySelector(".buttons");
      buttons.style.display = !online ? "block" : "none";
    });

    container.appendChild(peer);
  }
}

// Dummy integration with your backend functions (to be replaced with real ones)
function askFiles(peerId) {
  alert(`P${peerId} is asking for files...`);
  // Call your real function here
  // example: window.myP2P.askFiles(peerId);
}

function shareFiles(peerId) {
  alert(`P${peerId} is sharing files...`);
  // Call your real function here
  // example: window.myP2P.shareFiles(peerId);
}
