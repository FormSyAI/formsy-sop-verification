// The host receives geometry only; materials and model actions stay in this workbench.
const parameters = new URLSearchParams(location.search);
if (parameters.get("embed") === "1") {
  document.documentElement.classList.add("workbench-embedded");
  let parentOrigin;
  try {
    const configured = parameters.get("parent_origin");
    const url = new URL(configured || document.referrer);
    if (["http:", "https:"].includes(url.protocol) && (!configured || url.origin === configured.replace(/\/$/, "")))
      parentOrigin = url.origin;
  } catch {}
  if (parentOrigin && window.parent !== window) {
    const send = (message) => window.parent.postMessage(message, parentOrigin);
    let previousHeight = 0;
    let viewportReceived = false;
    const sendHeight = (force = false) => {
      const height = Math.ceil(document.body.getBoundingClientRect().height);
      if (force || height !== previousHeight) {
        previousHeight = height;
        send({ type: "formsy-sop-workbench:height", height });
      }
    };
    new ResizeObserver(() => sendHeight()).observe(document.body);
    window.addEventListener("hashchange", () => {
      let target;
      try { target = document.getElementById(decodeURIComponent(location.hash.slice(1))); } catch {}
      if (target) send({ type: "formsy-sop-workbench:scroll", top: target.getBoundingClientRect().top + window.scrollY });
    });
    window.addEventListener("message", (event) => {
      const data = event.data;
      if (event.source !== window.parent || event.origin !== parentOrigin ||
          data?.type !== "formsy-sop-workbench:viewport" ||
          !Number.isFinite(data.top) || !Number.isFinite(data.height) ||
          data.top < 0 || data.top > 100000 || data.height < 0 || data.height > 100000) return;
      document.documentElement.style.setProperty("--embed-visible-top", `${data.top}px`);
      document.documentElement.style.setProperty("--embed-visible-height", `${Math.max(200, data.height)}px`);
      if (!viewportReceived) {
        viewportReceived = true;
        sendHeight(true);
      }
    });
  }
}
