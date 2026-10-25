document.addEventListener('DOMContentLoaded', function () {
  const form = document.querySelector('.analyze-form');
  const statusBox = document.getElementById('formStatus');

  if (form) {
    form.addEventListener('submit', function (event) {
      const input = form.querySelector('input[name="url"]');
      if (!input || !input.value.trim()) {
        event.preventDefault();
        if (statusBox) {
          statusBox.textContent = 'Please enter a URL before submitting.';
          statusBox.style.color = '#f7d57b';
        }
        return;
      }

      if (statusBox) {
        statusBox.textContent = 'Analyzing URL...';
        statusBox.style.color = '#9ad0ff';
      }
    });
  }

  document.querySelectorAll('.sample-link').forEach(function (button) {
    button.addEventListener('click', function () {
      const input = document.getElementById('urlInput');
      if (input) {
        input.value = button.dataset.url || '';
      }
    });
  });
});
