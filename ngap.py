import json
import re
from flask import Flask, request, jsonify
from scapy.all import *
import pyshark
from pycrate_asn1dir import NGAP
app = Flask(__name__)

ngapMessage = {
    "procedureCode": 46,
    "criticality": "ignore",
    "value": [
        "UplinkNASTransport",
        {
            "protocolIEs": [
                {
                    "id": 10,
                    "criticality": "reject",
                    "value": [
                        "AMF-UE-NGAP-ID",
                        1
                    ]
                },
                {
                    "id": 85,
                    "criticality": "reject",
                    "value": [
                        "RAN-UE-NGAP-ID",
                        1
                    ]
                },
                {
                    "id": 38,
                    "criticality": "reject",
                    "value": [
                        "NAS-PDU",
                        "~\\x00W-\\x10\\xcb\\xa3b\\x8a\\xb6\\xe0P\\x90\\xee\\x95\\xad5~\\xc4\\\\2"
                    ]
                },
                {
                    "id": 121,
                    "criticality": "ignore",
                    "value": [
                        "UserLocationInformation",
                        [
                            "userLocationInformationNR",
                            {
                                "nR-CGI": {
                                    "pLMNIdentity": "\\x00\\xf1\\x10",
                                    "nRCellIdentity": [
                                        16,
                                        36
                                    ]
                                },
                                "tAI": {
                                    "pLMNIdentity": "\\x00\\xf1\\x10",
                                    "tAC": "\\x00\\x00\\x01"
                                },
                                "timeStamp": "\\xe8Q\\x12%"
                            }
                        ]
                    ]
                }
            ]
        }
    ]
}

@app.route('/', methods=['GET'])
def index():
    return '''
     <!DOCTYPE html>
<html>
<head>
    <title>NGAP Message</title>
</head>
<body>
    <h1>NGAP Message</h1>
    <div id="ngap-message"></div>
    <script>
 const ngapMessage = ''' + json.dumps(ngapMessage) + ''';

function displayObject(obj, container, parentObj, parentKey) {
    if (typeof obj === "object") {
        const table = document.createElement('table');
        table.border = '1';
        for (const key in obj) {
            const tr = document.createElement('tr');
            const th = document.createElement('th');
            th.textContent = key;
            tr.appendChild(th);
            const td = document.createElement('td');
            displayObject(obj[key], td, obj, key);
            tr.appendChild(td);
            table.appendChild(tr);
        }
        container.appendChild(table);
    } else if (Array.isArray(obj)) {
        const ul = document.createElement('ul');
        for (let i = 0; i < obj.length; i++) {
            const li = document.createElement('li');
            displayObject(obj[i], li, obj, i);
            ul.appendChild(li);
        }
        container.appendChild(ul);
    } else {
        const input = document.createElement('input');
        input.type = 'text';
        input.value = obj;
        input.addEventListener('input', function() {
            if (typeof obj === 'number') {
                parentObj[parentKey] = Number(this.value);
            } else {
                parentObj[parentKey] = this.value;
            }
        });
        container.appendChild(input);
    }
}
    const container = document.getElementById('ngap-message');
    displayObject(ngapMessage, container, ngapMessage, 'ngapMessage');

    </script>
    <button id='btn'>Submit</button>
    <script>
    const submitButton = document.getElementById('btn');
    submitButton.addEventListener('click', function() {
    fetch('http://127.0.0.1:5000', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(ngapMessage)
    });
});
    </script>
</body>
</html>
'''
# def update_hey(target, source):
#     for key, source_value in source.items():
#         if isinstance(source_value, dict):
#             target_value = target.get(key, {})
#             if isinstance(target_value, dict):
#                 update_hey(target_value, source_value)
#                 continue
#         elif isinstance(source_value, list):
#             target_value = target.get(key, [])
#             if isinstance(target_value, list):
#                 if len(target_value) != len(source_value):
#                     continue
#                 for i in range(len(target_value)):
#                     if isinstance(source_value[i], (dict, list)):
#                         update_hey(target_value[i], source_value[i])
#                         continue
#         else:
#             target_value = target.get(key)
        
#         # Update 'hey' if the values are different
#         if target_value != source_value:
#             target[key] = source_value
def change_data_structures(js, hey):
    def change_structure(js, hey):
        if isinstance(hey, dict):
            for key, value in hey.items():
                if key in js:
                    js[key] = change_structure(js[key], value)
            return js
        elif isinstance(hey, list) or isinstance(hey, tuple):
            return type(hey)([change_structure(js[i], hey[i]) for i in range(len(hey))])
        else:
            return js
    return change_structure(js, hey)
def convert_to_bytes(js):
    if isinstance(js, dict):
        for key, value in js.items():
            js[key] = convert_to_bytes(value)
    elif isinstance(js, list):
        for i, item in enumerate(js):
            js[i] = convert_to_bytes(item)
    elif isinstance(js, str):
        if(bool(re.match('^[a-z-A-Z0-9]*$',js))==False):
            u=js.encode('latin-1')
            string_value = u.decode('unicode_escape')
            u = string_value.encode('latin-1')
            # print(byte_value)
            js=u
    return js

# Convert strings back to bytes in 'js' before updating 'hey'

# @app.route('/update', methods=['POST'])
# def update():
#     ngap_message = request.get_json()
#     print('Data received:', ngap_message)
#     return "YAY"

# if __name__ == '__main__':
#     app.run(debug=True)
#     app.run(host='127.0.0.1', port=5000)
@app.route('/', methods=['GET', 'POST'])
def handle_request():
    if request.method == 'POST':
        c = pyshark.FileCapture("hello.pcap", use_json=True, include_raw=True)
        my_packet = c[2]
        js = request.get_json()
        scapy_packet = IP(my_packet.get_raw_packet())
        # print(js)
        x = NGAP.NGAP_PDU_Descriptions.NGAP_PDU
        x.from_aper(scapy_packet[SCTPChunkData].data)
        z=x.get_val()
        hey=[None]*2
        hey[0]=z[0]
        hey[1]=z[1]


        # o=hey[1]
        # print(z[1])
        # o=tuple(o)
        # print(o)
        # js = convert_strings_to_bytes(js)
        # update_hey(hey[1], js)
        print(js)
        print("\n")
        js=convert_to_bytes(js)
        js=change_data_structures(js,hey[1])
        print(js)
        # print("\n")
        # print(hey[1])
        # i=js
        # js=hey[1]
        # s=z[1]
        # a=x.get_val()
        # print(a[1])
        # print("\n")
        # print(js)
        # print(s)

        init_msg_pdu_modify_req = NGAP.NGAP_PDU_Descriptions.InitiatingMessage
        init_msg_pdu_modify_req.set_val(js)
        buf=init_msg_pdu_modify_req.to_aper()
        buf=b'\x00'+buf
        print(buf)
        scapy_packet[SCTPChunkData].data=buf
        send(scapy_packet)
        # print(buf)





        return 'POST request handled'
    else:
        return 'GET request handled'

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000)
