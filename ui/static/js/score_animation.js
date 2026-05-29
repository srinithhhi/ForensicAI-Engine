// Big-score number: initial count-up on load, plus an API the timeline uses to
// drive the cosmetic score-climb during replay. rAF-driven, ease-out cubic,
// tabular-nums so the width never reflows (no layout shift / jank).
(function () {
  "use strict";

  var el = document.getElementById("score-number");
  if (!el) return;

  var target = parseInt(el.getAttribute("data-target"), 10) || 0;
  var reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  function easeOutCubic(t) {
    return 1 - Math.pow(1 - t, 3);
  }

  // Animate the displayed integer from its current value to `to`.
  var rafId = null;
  function animateTo(to, duration) {
    if (rafId) cancelAnimationFrame(rafId);
    var from = parseInt(el.textContent, 10) || 0;
    if (reduce || duration <= 0 || from === to) {
      el.textContent = String(to);
      return;
    }
    var start = null;
    function frame(ts) {
      if (start === null) start = ts;
      var p = Math.min((ts - start) / duration, 1);
      el.textContent = String(Math.round(from + easeOutCubic(p) * (to - from)));
      if (p < 1) {
        rafId = requestAnimationFrame(frame);
      } else {
        el.textContent = String(to);
        rafId = null;
      }
    }
    rafId = requestAnimationFrame(frame);
  }

  // Public API for timeline.js.
  window.ForensicScore = {
    target: target,
    // Set instantly to an integer score (used while scrubbing playback).
    set: function (value) {
      if (rafId) {
        cancelAnimationFrame(rafId);
        rafId = null;
      }
      el.textContent = String(Math.max(0, Math.min(target, Math.round(value))));
    },
    // Smoothly settle to the final score.
    settle: function () {
      animateTo(target, 600);
    },
    reset: function () {
      this.set(0);
    },
  };

  // Initial headline reveal: count up 0 -> final.
  el.textContent = "0";
  animateTo(target, 900);
})();
