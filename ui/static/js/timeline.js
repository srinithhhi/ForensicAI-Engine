// Animated event timeline. Fetches /api/timeline/{id}, plots events in 6 OCSF
// lanes, and sweeps a vertical "now" line left->right revealing dots at their
// real timestamps. The big score climbs cosmetically as attack dots appear.
//
// Smoothness strategy: the sweep line moves every frame via a cheap relayout;
// dots are appended with Plotly.extendTraces only on frames where new ones
// cross the line (no full-array rebuilds). Reduced-motion users get the full
// static plot immediately.
(function () {
  "use strict";

  var host = document.querySelector("[data-incident]");
  var plotDiv = document.getElementById("timeline-plot");
  if (!host || !plotDiv || typeof Plotly === "undefined") return;

  var incidentId = host.getAttribute("data-incident");
  var summaryEl = document.getElementById("tl-summary");
  var playBtn = document.getElementById("tl-play");
  var playLabel = document.getElementById("tl-play-label");
  var restartBtn = document.getElementById("tl-restart");
  var speedBtns = Array.prototype.slice.call(document.querySelectorAll(".tl-speed"));

  var reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  var DIM_PINK = "#5c1733";
  var HOT_PINK = "#ff0080";
  var ACCENT = "#ec4899";
  var REPLAY_MS = 13000; // wall-clock duration of a full 1x replay

  // ---- state ----
  var data = null;
  var sorted = []; // dots sorted by time (from the API; already sorted)
  var idx = 0; // next dot to reveal
  var nowT = 0; // current sweep time (ms epoch)
  var startT = 0;
  var endT = 0;
  var span = 1;
  var attackShown = 0; // attack dots revealed so far
  var attackTotalShown = 1; // attack dots in the (downsampled) plot
  var speed = 1;
  var playing = false;
  var replaying = false; // a replay is in progress (possibly paused)
  var lastTs = null;
  var rafId = null;

  function sevSize(s, isAttack) {
    return (isAttack ? 6 : 4) + (s || 1) * 1.8;
  }
  function laneJitter(lane) {
    // Deterministic-ish vertical spread so stacked dots don't fully overlap.
    return lane + (Math.random() - 0.5) * 0.34;
  }

  function baseLayout() {
    return {
      paper_bgcolor: "rgba(0,0,0,0)",
      plot_bgcolor: "rgba(0,0,0,0)",
      margin: { l: 92, r: 16, t: 8, b: 28 },
      showlegend: false,
      hovermode: "closest",
      font: { family: "ui-monospace, monospace", size: 11, color: "#9a9aa8" },
      xaxis: {
        type: "date",
        range: [startT, endT],
        gridcolor: "rgba(255,255,255,0.045)",
        zeroline: false,
        linecolor: "rgba(255,255,255,0.08)",
        tickformat: "%H:%M",
      },
      yaxis: {
        range: [-0.7, data.lanes.length - 0.3],
        tickmode: "array",
        tickvals: data.lanes.map(function (_, i) { return i; }),
        ticktext: data.lanes,
        gridcolor: "rgba(255,255,255,0.045)",
        zeroline: false,
        linecolor: "rgba(255,255,255,0.08)",
      },
      shapes: [
        {
          type: "line",
          xref: "x",
          yref: "paper",
          x0: startT,
          x1: startT,
          y0: 0,
          y1: 1,
          line: { color: ACCENT, width: 1.5 },
          opacity: 0,
        },
      ],
    };
  }

  function emptyTraces() {
    return [
      {
        name: "benign",
        x: [], y: [], text: [],
        mode: "markers",
        type: "scatter",
        hovertemplate: "%{text}<extra></extra>",
        marker: { color: DIM_PINK, size: [], opacity: 0.5, line: { width: 0 } },
      },
      {
        name: "attack",
        x: [], y: [], text: [],
        mode: "markers",
        type: "scatter",
        hovertemplate: "%{text}<extra></extra>",
        marker: {
          color: HOT_PINK,
          size: [],
          opacity: 0.95,
          line: { width: 1, color: "rgba(255,0,128,0.5)" },
        },
      },
    ];
  }

  function dotText(d) {
    var tag = d.a ? (d.reason ? "[" + d.reason + "] " : "[attack] ") : "";
    return tag + (d.step ? d.step + " · " : "") + (d.msg || "");
  }

  // Append a batch of dots to their trace(s) via extendTraces.
  function revealBatch(batch) {
    if (!batch.length) return;
    var b = { x: [[]], y: [[]], text: [[]], "marker.size": [[]] };
    var a = { x: [[]], y: [[]], text: [[]], "marker.size": [[]] };
    for (var i = 0; i < batch.length; i++) {
      var d = batch[i];
      var dst = d.a ? a : b;
      dst.x[0].push(d.t);
      dst.y[0].push(laneJitter(d.lane));
      dst.text[0].push(dotText(d));
      dst["marker.size"][0].push(sevSize(d.s, d.a));
    }
    if (b.x[0].length) Plotly.extendTraces(plotDiv, b, [0]);
    if (a.x[0].length) Plotly.extendTraces(plotDiv, a, [1]);
  }

  function updateScore() {
    if (!window.ForensicScore) return;
    var frac = attackShown / attackTotalShown;
    window.ForensicScore.set(window.ForensicScore.target * Math.min(1, frac));
  }

  function setLine(t, visible) {
    Plotly.relayout(plotDiv, {
      "shapes[0].x0": t,
      "shapes[0].x1": t,
      "shapes[0].opacity": visible ? 0.9 : 0,
    });
  }

  function finish() {
    playing = false;
    replaying = false;
    playLabel.textContent = "Replay";
    setLine(endT, false);
    if (window.ForensicScore) window.ForensicScore.settle();
    if (rafId) { cancelAnimationFrame(rafId); rafId = null; }
    lastTs = null;
  }

  function frame(ts) {
    if (!playing) return;
    if (lastTs === null) lastTs = ts;
    var dtWall = ts - lastTs;
    lastTs = ts;

    // Advance sweep time proportionally: a full span takes REPLAY_MS at 1x.
    nowT += (span / REPLAY_MS) * dtWall * speed;
    if (nowT > endT) nowT = endT;

    var batch = [];
    while (idx < sorted.length && sorted[idx].t <= nowT) {
      var d = sorted[idx];
      batch.push(d);
      if (d.a) attackShown++;
      idx++;
    }
    if (batch.length) {
      revealBatch(batch);
      updateScore();
    }
    setLine(nowT, true);

    if (idx >= sorted.length && nowT >= endT) {
      finish();
      return;
    }
    rafId = requestAnimationFrame(frame);
  }

  // Clear the plot back to empty and rewind playback state. Resets the score
  // to 0 so the next replay climbs from scratch.
  function resetPlayback() {
    if (rafId) { cancelAnimationFrame(rafId); rafId = null; }
    playing = false;
    replaying = false;
    idx = 0;
    attackShown = 0;
    nowT = startT;
    lastTs = null;
    Plotly.react(plotDiv, emptyTraces(), baseLayout(), {
      displayModeBar: false,
      responsive: true,
    });
    if (window.ForensicScore) window.ForensicScore.reset();
    playLabel.textContent = "Play";
  }

  // Begin a replay from the start (clears whatever is shown first).
  function startReplay() {
    resetPlayback();
    replaying = true;
    playing = true;
    playLabel.textContent = "Pause";
    rafId = requestAnimationFrame(frame);
  }
  // Continue a paused mid-replay without rewinding.
  function resume() {
    playing = true;
    playLabel.textContent = "Pause";
    rafId = requestAnimationFrame(frame);
  }
  function pause() {
    playing = false;
    playLabel.textContent = "Play";
    if (rafId) { cancelAnimationFrame(rafId); rafId = null; }
    lastTs = null;
  }

  // On load (and reduced-motion), show the full picture at once. Leaves the
  // score alone so the headline count-up in score_animation.js owns it.
  function showFullStatic() {
    Plotly.react(plotDiv, emptyTraces(), baseLayout(), {
      displayModeBar: false,
      responsive: true,
    });
    revealBatch(sorted);
    setLine(endT, false);
    playLabel.textContent = "Play";
  }

  function wireControls() {
    playBtn.addEventListener("click", function () {
      if (playing) pause();
      else if (replaying) resume();
      else startReplay();
    });
    restartBtn.addEventListener("click", startReplay);
    speedBtns.forEach(function (btn) {
      btn.addEventListener("click", function () {
        speed = parseFloat(btn.getAttribute("data-speed")) || 1;
        speedBtns.forEach(function (b) { b.classList.remove("is-active"); });
        btn.classList.add("is-active");
      });
    });
    window.addEventListener("resize", function () {
      Plotly.Plots.resize(plotDiv);
    });
  }

  fetch("/api/timeline/" + encodeURIComponent(incidentId))
    .then(function (r) { return r.json(); })
    .then(function (payload) {
      data = payload;
      sorted = payload.events || [];
      startT = payload.window.start_ms;
      endT = payload.window.end_ms;
      span = Math.max(1, endT - startT);
      attackTotalShown = Math.max(1, sorted.filter(function (d) { return d.a; }).length);

      summaryEl.textContent =
        sorted.length +
        " of " +
        payload.total_events.toLocaleString() +
        " events · " +
        payload.attack_total.toLocaleString() +
        " attack-flagged";

      Plotly.newPlot(plotDiv, emptyTraces(), baseLayout(), {
        displayModeBar: false,
        responsive: true,
      });

      wireControls();

      // Show the full timeline immediately as the "here's the picture" state;
      // the headline score counts up independently. Pressing Play clears it
      // and replays the sweep while the score climbs from 0. Reduced-motion
      // users just keep the static view.
      showFullStatic();
    })
    .catch(function () {
      summaryEl.textContent = "timeline unavailable";
    });
})();
