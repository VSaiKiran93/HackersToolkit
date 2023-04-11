// Get the form element
    // const scanForm = document.querySelector('#scan-form');

    // Get the output container element
    const outputContainer = document.querySelector('#output-container');

    // Add an event listener to the form submit button
    // scanForm.addEventListener('submit', async (event) => {
    //     // Prevent the form from submitting normally
    //     event.preventDefault();

    //     // Get the IP address and scan type values from the form
    //     const formData = new FormData(event.target);
    //     const ip = formData.get('ip');
    //     const scanType = formData.get('scan_type');

    //     try {
    //         // Make an API call to the Django view using fetch()
    //         const response = await fetch('{% url 'nmap' %}', {
    //             method: 'POST',
    //             body: formData
    //         });

    //         // Parse the response as JSON
    //         const data = await response.json();

    //         // Display the scan results in the output container
    //         outputContainer.innerHTML = '<pre>' + data.output_list.join('\n') + '</pre>';
    //     } catch (error) {
    //         // Display an error message if there was an error
    //         outputContainer.innerHTML = '<p>An error occurred while scanning.</p>';
    //     }
    // });

    let loginForm = document.getElementById("loginForm");

    loginForm.addEventListener("submit", (e) => {
    e.preventDefault();

        let ip_address = document.getElementById("input-text");
        let scan_type = document.getElementById("scan-type");

        if (ip_address.value == "" || scan_type.value == "") {
        alert("Ensure you input a value in both fields!");
        } else {
        // perform operation with form input
        let obj = {
            'ip':ip_address.value, 
            "scan_type": scan_type.value
        }
            try {
                console.log("payload....",obj)
                    // Make an API call to the Django view using fetch()
                    const response = await fetch("http://127.0.0.1:8000", {
                        method: 'POST',
                        body: obj
                    });
        
                    // Parse the response as JSON
                    const data = await response.json();
                    console.log("response",data);
                    // Display the scan results in the output container
                    outputContainer.innerHTML = '<pre>' + data.output_list.join('\n') + '</pre>';
                    } catch (error) {
                    // Display an error message if there was an error
                    console.log(error);
                    outputContainer.innerHTML = '<p>An error occurred while scanning.</p>';
                }
        console.log(
        `This form has a ip_address of ${ip_address.value} and scan_type of ${scan_type.value}`
        );

        // ip_address.value = "";
        // scan_type.value = "";
        }
        
    });