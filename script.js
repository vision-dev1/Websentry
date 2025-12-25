document.addEventListener('DOMContentLoaded', () => {
    const scanForm = document.querySelector('form');
    const urlInput = document.querySelector('input[type="url"]');
    const scanButton = document.querySelector('button[type="button"]');
    const resultsContainer = document.querySelector('.mt-6');

    const permissionContainer = document.createElement('div');
    permissionContainer.className = 'flex items-center gap-2 mb-4';
    permissionContainer.innerHTML = `
        <input type="checkbox" id="scan-permission" class="rounded text-primary focus:ring-primary border-slate-300 dark:border-slate-600 dark:bg-slate-800">
        <label for="scan-permission" class="text-xs text-slate-500 dark:text-slate-400 select-none cursor-pointer">
            I am authorized to scan this target (Ethical Use Only).
        </label>
    `;

    scanForm.insertBefore(permissionContainer, scanButton);
    const permissionCheckbox = document.getElementById('scan-permission');

    const errorContainer = document.createElement('div');
    errorContainer.className = 'text-red-500 text-xs font-medium mt-2 hidden';
    urlInput.parentElement.parentElement.appendChild(errorContainer);

    const originalButtonText = scanButton.innerHTML;

    function showError(message) {
        errorContainer.textContent = message;
        errorContainer.classList.remove('hidden');
        urlInput.classList.add('border-red-500', 'focus:ring-red-500');
        urlInput.classList.remove('focus:ring-primary');
    }

    function clearError() {
        errorContainer.classList.add('hidden');
        urlInput.classList.remove('border-red-500', 'focus:ring-red-500');
        urlInput.classList.add('focus:ring-primary');
    }

    function createResultCard(name, data) {
        let severity = 'LOW';
        let colorClass = 'border-green-500 bg-green-50 text-green-700 dark:bg-green-900/20 dark:text-green-300';
        let icon = 'check_circle';

        const status = data.status.toLowerCase();

        if (['vulnerable', 'insecure', 'expired', 'high', 'critical'].includes(status)) {
            severity = 'HIGH';
            colorClass = 'border-red-500 bg-red-50 text-red-700 dark:bg-red-900/20 dark:text-red-300';
            icon = 'warning';
        } else if (['warning', 'expiring_soon', 'redirects', 'info'].includes(status)) {
            if (status === 'info') {
                severity = 'INFO';
                colorClass = 'border-blue-500 bg-blue-50 text-blue-700 dark:bg-blue-900/20 dark:text-blue-300';
                icon = 'info';
            } else {
                severity = 'MEDIUM';
                colorClass = 'border-yellow-500 bg-yellow-50 text-yellow-700 dark:bg-yellow-900/20 dark:text-yellow-300';
                icon = 'error';
            }
        }

        return `
            <div class="p-3 mb-2 rounded border-l-4 ${colorClass} transition-all animate-fade-in relative group/card">
                <div class="flex justify-between items-start">
                    <div class="flex items-center gap-2">
                        <span class="material-symbols-outlined text-sm pt-0.5">${icon}</span>
                        <span class="font-bold text-sm">${name}</span>
                    </div>
                    <span class="text-[10px] uppercase font-bold px-2 py-0.5 rounded bg-white/50 backdrop-blur-sm shadow-sm">${severity}</span>
                </div>
                <p class="text-xs mt-1 opacity-90 leading-relaxed">${data.message}</p>
                ${data.details ? `<div class="mt-2 text-[10px] font-mono bg-black/5 dark:bg-white/5 p-2 rounded overflow-x-auto whitespace-pre-wrap hidden group-hover/card:block transition-all">${JSON.stringify(data.details, null, 2).replace(/[{}"]/g, '')}</div>` : ''}
            </div>
        `;
    }

    scanButton.addEventListener('click', async (e) => {
        e.preventDefault();
        clearError();

        const url = urlInput.value.trim();

        if (!url) {
            showError('Please enter a target URL.');
            return;
        }

        if (!url.startsWith('http://') && !url.startsWith('https://')) {
            showError('URL must start with http:// or https://');
            return;
        }

        if (!permissionCheckbox.checked) {
            showError('You must verify authorization to scan this target.');
            return;
        }

        scanButton.disabled = true;
        scanButton.innerHTML = `
            <span class="animate-spin material-symbols-outlined text-[20px] mr-2">progress_activity</span>
            Scanning...
        `;

        resultsContainer.innerHTML = '';
        resultsContainer.className = 'mt-6 flex flex-col gap-2';

        const statusIndicator = document.createElement('div');
        statusIndicator.className = 'text-center text-sm text-slate-500 py-4 italic animate-pulse';
        statusIndicator.textContent = 'Analyzing target security posture...';
        resultsContainer.appendChild(statusIndicator);

        try {
            const apiEndpoint = '/scan';

            const response = await fetch(apiEndpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ url: url })
            });

            if (!response.ok) {
                const errData = await response.json().catch(() => ({}));
                throw new Error(errData.error || `Server error: ${response.status}`);
            }

            const data = await response.json();

            resultsContainer.innerHTML = '';

            if (!data.checks || Object.keys(data.checks).length === 0) {
                resultsContainer.innerHTML = '<div class="text-center text-slate-500 text-sm">No results returned.</div>';
            } else {
                Object.entries(data.checks).forEach(([name, result]) => {
                    resultsContainer.innerHTML += createResultCard(name, result);
                });

                const footer = document.createElement('div');
                footer.className = 'mt-2 text-[10px] text-center text-slate-400';
                footer.textContent = `Scan ID: ${data.timestamp} • Target: ${data.url}`;
                resultsContainer.appendChild(footer);
            }

        } catch (error) {
            console.error('Scan failed:', error);
            resultsContainer.innerHTML = `
                <div class="p-4 bg-red-50 dark:bg-red-900/10 border border-red-200 dark:border-red-800 rounded-lg text-center">
                    <span class="material-symbols-outlined text-red-500 block mb-2">wifi_off</span>
                    <p class="text-xs text-red-600 dark:text-red-400 font-bold">Scan Failed</p>
                    <p class="text-xs text-red-500 dark:text-red-400 mt-1">${error.message === 'Failed to fetch' ? 'Backend not reachable. Is scanner.py running?' : error.message}</p>
                </div>
            `;
        } finally {
            scanButton.disabled = false;
            scanButton.innerHTML = originalButtonText;
        }
    });
});
