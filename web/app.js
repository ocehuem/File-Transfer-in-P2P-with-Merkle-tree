function startPeer(peerPort, peerDirectory) {
    const port = peerPort;
  const directory = peerDirectory;
    fetch('/api/start', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        port: parseInt(port),
        directory: directory
      })
    })
    .then(response => response.json())
    .then(data => {
      if (data.success) {
        alert("Peer started successfully!");
      } else {
        alert("Error: " + data.error);
      }
    });
  }



  function generatePeers() {
    const count = parseInt(document.getElementById("peerCount").value);
    const container = document.getElementById("peerContainer");
    container.innerHTML = "";
  
    for (let i = 1; i <= count; i++) {
      
      const peer = document.createElement("div");

      peer.className = "peer";
      peer.id = `peer-${i}`;
      peer.dataset.online = "false";
      const peerPort = 8000+i;
      const peerDirectory = peer.id;
  
      peer.innerHTML = `
        <div><strong>P${i}</strong></div>
        <div class="buttons" style="display: none;">
        </div>
      `;
  
      peer.addEventListener("click", function(e) {
        if (e.target.tagName === 'BUTTON') return; // ignore button clicks
        const online = peer.dataset.online === "true";
        peer.dataset.online = (!online).toString();
        peer.classList.toggle("online", !online);
        const buttons = peer.querySelector(".buttons");
        buttons.style.display = !online ? "block" : "none";
        startPeer(peerPort, peerDirectory);
      });
  
      container.appendChild(peer);
    }
  }
