// Upload flow: drag-drop a zip, POST it, poll the job, redirect to dashboard.
// Kept dependency-free (no framework) so there's nothing to re-render and jank.
(function () {
  "use strict";

  var form = document.getElementById("upload-form");
  if (!form) return;

  var dropzone = document.getElementById("dropzone");
  var fileInput = document.getElementById("file-input");
  var filenameEl = document.getElementById("filename");
  var submitBtn = document.getElementById("submit-btn");
  var progress = document.getElementById("progress");
  var statusPill = document.getElementById("status-pill");
  var logEl = document.getElementById("log");

  function setFile(file) {
    if (!file) return;
    if (!file.name.toLowerCase().endsWith(".zip")) {
      filenameEl.textContent = "✕ not a .zip file";
      filenameEl.classList.remove("hidden");
      submitBtn.disabled = true;
      return;
    }
    // Reflect the chosen file in the hidden input for native form semantics.
    var dt = new DataTransfer();
    dt.items.add(file);
    fileInput.files = dt.files;
    filenameEl.textContent = file.name;
    filenameEl.classList.remove("hidden");
    submitBtn.disabled = false;
  }

  fileInput.addEventListener("change", function () {
    if (fileInput.files.length) setFile(fileInput.files[0]);
  });

  // Drag styling + drop handling.
  ["dragenter", "dragover"].forEach(function (evt) {
    dropzone.addEventListener(evt, function (e) {
      e.preventDefault();
      dropzone.classList.add("border-pink-500");
      dropzone.style.boxShadow = "0 0 24px -4px rgba(236,72,153,0.45)";
    });
  });
  ["dragleave", "drop"].forEach(function (evt) {
    dropzone.addEventListener(evt, function (e) {
      e.preventDefault();
      dropzone.classList.remove("border-pink-500");
      dropzone.style.boxShadow = "";
    });
  });
  dropzone.addEventListener("drop", function (e) {
    if (e.dataTransfer.files.length) setFile(e.dataTransfer.files[0]);
  });

  function appendLog(lines) {
    logEl.textContent = lines.join("\n");
    logEl.scrollTop = logEl.scrollHeight;
  }

  function poll(jobId) {
    fetch("/api/jobs/" + jobId)
      .then(function (r) { return r.json(); })
      .then(function (job) {
        appendLog(job.log_lines || []);
        if (job.status === "done") {
          statusPill.textContent = "done";
          window.location.href = "/dashboard/" + job.incident_id;
          return;
        }
        if (job.status === "error") {
          statusPill.textContent = "error";
          statusPill.className = "pill bg-ink-600 text-pink-300";
          document.getElementById("progress-sweep").style.display = "none";
          return;
        }
        setTimeout(function () { poll(jobId); }, 700);
      })
      .catch(function () {
        setTimeout(function () { poll(jobId); }, 1200);
      });
  }

  form.addEventListener("submit", function (e) {
    e.preventDefault();
    if (!fileInput.files.length) return;

    submitBtn.disabled = true;
    submitBtn.textContent = "Uploading…";
    progress.classList.remove("hidden");

    var data = new FormData();
    data.append("file", fileInput.files[0]);

    fetch("/api/upload", { method: "POST", body: data })
      .then(function (r) {
        return r.json().then(function (body) {
          if (!r.ok) throw new Error(body.detail || "upload failed");
          return body;
        });
      })
      .then(function (body) {
        submitBtn.textContent = "Processing…";
        poll(body.job_id);
      })
      .catch(function (err) {
        statusPill.textContent = "error";
        statusPill.className = "pill bg-ink-600 text-pink-300";
        appendLog([String(err.message || err)]);
        submitBtn.disabled = false;
        submitBtn.textContent = "Run pipeline";
      });
  });
})();
