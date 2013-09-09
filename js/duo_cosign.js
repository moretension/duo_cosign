function createRadioButton( name, value, id, checked ) {
    var	radio;
    var d = {"name": name, "type": "radio", "value": value, "id": id};

    radio = document.createElement( 'input' );
    for ( k in d ) {
	radio.setAttribute( k, d[k] );
    }
    if ( checked ) {
	radio.setAttribute( 'checked', checked );
    }

    return( radio );
}

function createLabel( forId, value ) {
    var	label;

    label = document.createElement( 'label' );
    label.setAttribute( 'for', forId );
    label.innerHTML = value;

    return( label );
}

function createPasswordInput( name, value, id ) {
    var	passwordInput;
    var d = {"name": name, "type": "password", "value": value, "id": id,
		"style": "width:6em;margin-left:5px"};

    passwordInput = document.createElement( 'input' );
    for ( var k in d ) { 
	passwordInput.setAttribute( k, d[k] );
    }

    return( passwordInput );
}

function duoDeviceListCapabilities( dev, dev_elem_ids ) {
    var	para, radio, label, passcodeInput;
    var i, len;
    var	selected = false;
    var capa = dev.capabilities;
    var capaText = {"push": "Push to Duo Mobile app",
			"phone": "Call my phone",
			"sms": "Text me passcodes",
			"passcode": "Passcode:"};

    console.log( 'ADMORTEN DEBUG: capabilities: ' + dev.capabilities );

    capa.push( 'passcode' );
    for ( i = 0; i < capa.length; i++ ) {
	radio = createRadioButton( 'duo_factor', capa[ i ],
				    'duoFactor' + (i + 1), false );
	radio.onclick = function() {
	    document.loginform.duo_device.value = dev.device;
	    document.getElementById( dev_elem_ids['passcode'] ).value = null;
	};
	if ( !selected ) {
	    selected = radio.checked = true;
	}

	label = createLabel( 'duoFactor' + (i + 1), capaText[ capa[ i ]] );
	
	passcodeInput = null;
	if ( capa[ i ] === "passcode" ) {
	    var	radioId = 'duoFactor' + (i + 1);

	    radio.onclick = function() {
		document.getElementById( dev_elem_ids['passcode'] ).focus();
		document.loginform.duo_device.value = null;
	    }
	    passcodeInput = createPasswordInput( 'duo_passcode', '',
					dev_elem_ids['passcode'] );

	    passcodeInput.onclick = function() {
		document.getElementById( radioId ).checked = true;
		document.loginform.duo_device.value = null;
	    }
	    passcodeInput.onfocus = passcodeInput.onclick;
	}

	para = document.createElement( 'p' );
	para.appendChild( radio );
	para.appendChild( label );
	if ( passcodeInput ) {
	    para.appendChild( passcodeInput );
	}

	document.getElementById( dev_elem_ids['capabilityList'] ).appendChild( para );
    }

    if ( i == 0 ) {
	throw( "No Duo authentication capabilities found for device!" );
    }
}
