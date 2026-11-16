const form = document.querySelector('#upload-form');
if (form) {
  const file = document.querySelector('#sample');
  const filename = document.querySelector('#filename');
  const status = document.querySelector('#status');
  const button = document.querySelector('#submit');
  const dropzone = document.querySelector('#dropzone');
  let timer;
  const show = (message) => { status.hidden = false; status.textContent = message; };
  file.addEventListener('change', () => { filename.textContent = file.files[0]?.name || 'Choose a sample'; });
  for (const event of ['dragover', 'dragenter']) dropzone.addEventListener(event, (e) => { e.preventDefault(); dropzone.classList.add('active'); });
  dropzone.addEventListener('dragleave', () => dropzone.classList.remove('active'));
  dropzone.addEventListener('drop', (e) => {
    e.preventDefault(); dropzone.classList.remove('active');
    if (e.dataTransfer.files.length) { file.files = e.dataTransfer.files; file.dispatchEvent(new Event('change')); }
  });
  const labels = { queued: 'Queued for analysis…', retry_queued: 'Retrying analysis…', static_analysis: 'Extracting static evidence…', ai_analysis: 'OpenCode + Mistral are analyzing the evidence…', publishing: 'Publishing report…' };
  async function poll(id) {
    try {
      const response = await fetch(`/api/analyses/${encodeURIComponent(id)}`);
      if (!response.ok) throw new Error('Could not retrieve analysis status.');
      const job = await response.json();
      if (job.status === 'completed') {
        sessionStorage.removeItem('analysis-id');
        show('Analysis complete. Opening report…');
        window.location.assign(job.report_url);
      } else if (job.status === 'failed') {
        sessionStorage.removeItem('analysis-id');
        show(job.error || 'Analysis failed.'); button.disabled = false;
      } else {
        const activity = job.activity ? ` ${job.activity}.` : '';
        const calls = job.tool_calls ? ` ${job.tool_calls} tool calls.` : '';
        show(`${labels[job.stage] || job.stage}${activity}${calls} Attempt ${job.attempts || 1}`);
        timer = setTimeout(() => poll(id), 2000);
      }
    } catch (error) {
      show(`${error.message} Retrying status check…`);
      timer = setTimeout(() => poll(id), 5000);
    }
  }
  form.addEventListener('submit', async (event) => {
    event.preventDefault(); clearTimeout(timer); button.disabled = true; show('Uploading sample…');
    try {
      const headers = {};
      const key = document.querySelector('#api-key')?.value;
      if (key) headers['X-API-Key'] = key;
      const response = await fetch('/api/samples', { method: 'POST', body: new FormData(form), headers });
      const data = await response.json();
      if (!response.ok) throw new Error(typeof data.detail === 'string' ? data.detail : 'Upload failed.');
      sessionStorage.setItem('analysis-id', data.id);
      await poll(data.id);
    } catch (error) { show(error.message); button.disabled = false; }
  });
  const existing = sessionStorage.getItem('analysis-id');
  if (existing) { button.disabled = true; poll(existing); }
}
