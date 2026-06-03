function safePost(frame, payload) {
  try {
    frame?.contentWindow?.postMessage(payload, "*");
  } catch {
    // no-op
  }
}

export function createStep3V2Tab({ src = "./step3_v2.html" } = {}) {
  const state = {
    host: null,
    frame: null,
    mounted: false,
  };

  function buildFrame() {
    const f = document.createElement("iframe");
    f.className = "step3-v2-frame";
    f.title = "Step 3 V2 Live Dashboard";
    f.loading = "eager";
    f.setAttribute("referrerpolicy", "no-referrer");
    f.src = src;
    return f;
  }

  function clearFrame() {
    if (!state.frame) return;
    safePost(state.frame, { type: "step3_v2:pause" });
    // Force unload so EventSource/timers stop in the child context.
    state.frame.src = "about:blank";
    state.frame.remove();
    state.frame = null;
  }

  function mount(hostEl) {
    state.host = hostEl;
    state.mounted = true;
    if (!state.frame) {
      state.frame = buildFrame();
    }
    if (!state.host.contains(state.frame)) {
      state.host.innerHTML = "";
      state.host.appendChild(state.frame);
    }
  }

  function onShow() {
    if (!state.host || !state.mounted) return;
    if (!state.frame) {
      state.frame = buildFrame();
      state.host.innerHTML = "";
      state.host.appendChild(state.frame);
    }
    safePost(state.frame, { type: "step3_v2:resume" });
  }

  function onHide() {
    clearFrame();
  }

  function destroy() {
    clearFrame();
    if (state.host) state.host.innerHTML = "";
    state.host = null;
    state.mounted = false;
  }

  return {
    mount,
    onShow,
    onHide,
    destroy,
  };
}
