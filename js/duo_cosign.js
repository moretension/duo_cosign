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
    var	capaDiv, para, radio, label, passcodeInput;
    var i, len;
    var	selected = false;
    var capa = [];
    var capaText = {"push": "Push to Duo Mobile app",
			"phone": "Call my phone",
			"sms": "Text me passcodes",
			"passcode": "Passcode:"};

    console.log( 'DEBUG: capabilities: ' + dev.capabilities );

    capaDiv = document.createElement( 'div' );
    capaDiv.setAttribute( 'id', dev_elem_ids['capabilityList'] + 'Options' );

    capa = capa.concat( dev.capabilities );
    if ( !( capa.length == 1 && capa[ 0 ] == "phone" )) {
	// only include passcode for smartphones (OATH, SMS),
	// tablets/iPod touches (OATH), and mobile phones (SMS)
	if ( capa.slice( -1 ) != "passcode" ) {
	    capa.push( 'passcode' );
	}
    }
    for ( i = 0; i < capa.length; i++ ) {
	console.log( 'DEBUG: capability: ' + capa[ i ] );

	radio = createRadioButton( 'duo_factor', capa[ i ],
				    'duoFactor' + (i + 1), false );
	radio.onclick = function() {
	    document.loginform.duo_device.value = dev.device;
	    document.getElementById( dev_elem_ids['passcode'] ).value = null;
	};
	if ( !selected ) {
	    document.loginform.duo_device.value = dev.device;
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

	capaDiv.appendChild( para );
    }

    if ( i == 0 ) {
	throw( "No Duo authentication capabilities found for device!" );
    }

    return( capaDiv );
}

function duoDeviceCreateSelectElement( devices ) {
    var	displayNames = [];
    var selAttr = {"name": "devices", "id": "duoDeviceSelect"};
    var selected = 0;
    var sel = null;
    var opt = null;

    sel = document.createElement( 'select' );
    for ( var k in selAttr ) {
	sel.setAttribute( k, selAttr[k] );
    }

    for ( var i = 0; i < devices.length; i++ ) {
	opt = document.createElement( 'option' );
	opt.innerHTML = devices[ i ]['display_name'];

	if ( !selected ) {
	    opt.selected = selected = 1;
	}

	sel.appendChild( opt );
    }

    return( sel );
}
