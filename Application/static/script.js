const userAction = async () => {
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
	console.log(obj);
        try {
        const response = await fetch('http://192.168.0.141:8000/nmap-scan/', {
          method: 'POST',
          body: obj, // string or object
          headers: {
            'Content-Type': 'application/json'
          }
        });
        console.log("api response",response)
        }catch(error){
            console.log(error)
        }
    }
}
