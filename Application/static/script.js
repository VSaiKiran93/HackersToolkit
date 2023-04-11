// Get the form element
    const scanForm = document.querySelector('#scan-form');

    // Get the output container element
    const outputContainer = document.querySelector('#output-container');

    // Add an event listener to the form submit button
    scanForm.addEventListener('submit', async (event) => {
        // Prevent the form from submitting normally
        event.preventDefault();

        // Get the IP address and scan type values from the form
        const formData = new FormData(event.target);
        const ip = formData.get('ip');
        const scanType = formData.get('scan_type');

        try {
            // Make an API call to the Django view using fetch()
            const response = await fetch('{% url 'nmap' %}', {
                method: 'POST',
                body: formData
            });

            // Parse the response as JSON
            const data = await response.json();

            // Display the scan results in the output container
            outputContainer.innerHTML = '<pre>' + data.output_list.join('\n') + '</pre>';
        } catch (error) {
            // Display an error message if there was an error
            outputContainer.innerHTML = '<p>An error occurred while scanning.</p>';
        }
    });
