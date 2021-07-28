/*

		Scripts for script.html
		Copyright (C) 2021	Maurice Lambert

		This program is free software: you can redistribute it and/or modify
		it under the terms of the GNU General Public License as published by
		the Free Software Foundation, either version 3 of the License, or
		(at your option) any later version.

		This program is distributed in the hope that it will be useful,
		but WITHOUT ANY WARRANTY; without even the implied warranty of
		MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	See the
		GNU General Public License for more details.

		You should have received a copy of the GNU General Public License
		along with this program.	If not, see <https://www.gnu.org/licenses/>.

*/

let script_name;
let script;
let download_extension=".txt";
let download_text="";
let download_type="plain"
let download_separator="\n";
let execution_number = 0;
let progress = true;
let is_running = false;

function build_script_interface (scripts) {
	script = scripts[script_name];

	add_description(script);
	add_arguments(script);
}

function add_description (script) {
	document.getElementById("script_description").innerText = script.description;
}

function add_arguments (script) {
	let arg;
	let argument;
	let div;
	let label;
	let paragraph;

	let submit_row = document.getElementById("submit_row");
	let script_interface = document.getElementById("script_interface");
	let input_wrapper;

	for (let i=0; i < script.args.length; ++i) {
		arg=script.args[i];
		input_wrapper = document.createElement("div");
		input_wrapper.classList.add("input_wrapper");

		if (arg.predefined_values !== undefined && arg.predefined_values !== null) {
			argument = add_argument_select(arg);
		} else {
			argument = get_input(arg);
		}

		input_wrapper.appendChild(argument);

		label = document.createElement("label");
		label.htmlFor = argument.name;
		label.innerText = argument.name + " :";
		label.classList.add("inline");
		label.classList.add("script_presentation");

		paragraph = document.createElement("p");
		paragraph.classList.add("inline");
		paragraph.classList.add("description");
		paragraph.classList.add("script_presentation");

		if (arg.description !== undefined && arg.description !== null) {
			paragraph.innerText = arg.description;
		}

		input_wrapper.classList.add("inline");

		div = document.createElement("div");
		div.classList.add("row");
		div.appendChild(label);
		div.appendChild(paragraph);
		div.appendChild(input_wrapper);

		script_interface.insertBefore(div, submit_row);
	}

	add_button();
	url_default_values();
}

function start_script_execution (event) {
	let arguments_ = get_arguments();
	arguments_ = make_json_request(arguments_);
	send_request(arguments_);
}

function get_arguments () {
	let input, select, option;
	let inputs = document.getElementsByTagName('input');
	let selects = document.getElementsByTagName('select');
	let arguments_ = {};

	for (let i=0; i < inputs.length; ++i) {
		input = inputs[i];

		if (input.type === "submit" || input.name === "csrf_token") {
			continue;
		}

		if (input.type === "checkbox") {
			arguments_ = add_value_for_request(arguments_, input.name, input.checked);
		} else {
			arguments_ = add_value_for_request(arguments_, input.name, input.value);			
		}

	}

	for (let i=0; i < selects.length; ++i) {
		select = selects[i];

		for (let l=0; l < select.options.length; ++l) {
			option = select.options[l];

			if (option.selected) {
				arguments_ = add_value_for_request(arguments_, select.name, option.value);
			}
		}
	}

	return arguments_;
}

function add_value_for_request(arguments_, name, value) {
	if (arguments_[name] !== undefined) {
		if (!Array.isArray(arguments_[name]["value"])) {
			arguments_[name]["value"] = [arguments_[name]["value"]];
		}

		if (value) {
			arguments_[name]["value"].push(value);
		}
	} else {
		arguments_[name] = {"value": value};

		let arg;
		for (let i=0; i < script.args.length; ++i) {
			arg=script.args[i];

			if (arg.name !== name) {
				continue;
			}

			if (arg.input === true) {
				arguments_[name]["input"]=true;
				break;
			} else {
				arguments_[name]["input"]=false;
				break;
			}
		}
	}

	return arguments_;
}

function make_json_request (arguments_) {
	let csrf = document.getElementById("csrf_token");
	return JSON.stringify(
		{
			"csrf_token": csrf.value, 
			"arguments": arguments_,
		}
	);
}

function send_request (json) {

	let xhttp = new XMLHttpRequest();
	xhttp.onreadystatechange = () => {
		if (xhttp.readyState === 4 && xhttp.status === 200) {
			let response_object = JSON.parse(xhttp.responseText);
			document.getElementById("csrf_token").value = response_object.csrf;
			build_output_interface(
				response_object
			);
		} else if (xhttp.readyState === 4 && xhttp.status === 302 && script_name === "/auth/") {
			window.location = new URL("/web/", window.location);
		}

		is_running = false;
	}

	let url;
	if (script_name === "/auth/") {
		url = script_name;
	} else {
		url = "/api/scripts/" + script_name;
	}

	xhttp.open("POST", url, true);
	xhttp.setRequestHeader('Content-Type', 'application/json');
	xhttp.send(json);

	is_running = true;
	progress_bar();
}

function build_output_interface (output, add_history_=true) {
	let console_div = document.getElementById("script_outputs");
	let content_type = output["Content-Type"];
	let new_output = document.createElement("div");

	if (add_history_) {
		add_history(
			`${output.stdout}${output.stderr}`, 
			output.code, 
			output.error, 
			content_type
		);
	}

	let console_ = document.createElement("pre");
	console_.id="console";
	console_.classList.add("console");

	let code = document.createElement("code");
	code.id="code";
	code.classList.add("code");
	code.innerText = `>>> ${script_name}\tExitCode: ${output.code}\tError: ${output.error}`;

	console_.appendChild(code);
	new_output.appendChild(console_);

	if (content_type.includes("text/html")) {
		download_extension = ".html";
		download_separator = "\n<br>\n";
		download_type = "html";
		new_output.innerHTML += `${output.stdout}${output.stderr}`;
	} else {
		download_extension = ".txt";
		download_separator = "\n";
		download_type = "plain";
		code.innerText += `\n${output.stdout}${output.stderr}\n`;
	}

	console_div.appendChild(new_output);
	download_text += `${output.stdout}${output.stderr}${download_separator}`;

	if (localStorage.getItem('theme') === "light") {
		light_mode(class_name='light', element=new_output);
	} else if (localStorage.getItem('theme') === null) {
		light_mode(class_name='default_theme', element=new_output);
	}
}

function add_history (value, code, error, content_type) {
	let button = document.createElement("button");
	button.onclick=build_output_interface.bind(
		button, 
		{
			'stdout': value, 
			'stderr': '',
			'code': code,
			'error': error,
			'Content-Type': content_type,
		},
		add_history_=false
	);
	button.innerText=execution_number;
	execution_number++;
	document.getElementById("webscripts_border_right").appendChild(button);

	if (localStorage.getItem('theme') === "light") {
		button.classList.toggle("light");
	} else if (localStorage.getItem('theme') === null) {
		button.classList.toggle("default_theme");
	}
}

function add_argument_select (argument) {
	let option;
	let select = document.createElement("select");
	select.id = argument.name;
	select.name = argument.name;

	if (argument.list) {
		select.multiple=true;
	}

	if (argument.default_value !== undefined && argument.default_value !== null) {
		select.value = argument.default_value;
	}

	for (let i=0; i < argument.predefined_values.length; ++i) {
		option = document.createElement("option");
		option.innerText = argument.predefined_values[i];
		option.value = argument.predefined_values[i];

		select.appendChild(option);
	}

	return select;
}

function get_input (arg) {
	let input = document.createElement("input");
	input.id = arg.name;
	input.name = arg.name;
	input.type = arg.html_type;

	if (arg.default_value !== undefined && arg.default_value !== null) {
		input.value = arg.default_value
	} 
	if (arg.example !== undefined && arg.example !== null) {
		input.placeholder = arg.example;
	}
	if (arg.list) {
		input.id=input.name+document.getElementsByName(
			input.name
		).length;
		input.onchange = input_list;
	}

	return input;
}

function input_list (event) {
	let source = event.target || event.srcElement;

	let next_id = source.id.substring(0, source.id.length - 1) + (parseInt(source.id[source.id.length - 1]) + 1);
	let next = document.getElementById(next_id);

	if (source.value === "" && (next !== null || next.value === "")) {
		next.remove();
	} else if (source.value !== "" && next === null) {
		new_element = source.cloneNode()
		new_element.id = source.name+document.getElementsByName(source.name).length;
		source.parentNode.appendChild(new_element);
		new_element.onchange=input_list;
		new_element.value="";
	}
}

function clear_console () {
	document.getElementById("script_outputs").innerText="";
	download_text = "";
}

function clear_history () {
	execution_number=0;
	document.getElementById("webscripts_border_right").innerText="";
}

function index_page () {
	window.location = new URL("/web/", window.location);
}

function download() {
		let download_link = document.createElement('a');
		download_link.setAttribute('href', `data:text/${download_type};charset=utf-8,` + encodeURIComponent(download_text));
		download_link.setAttribute('download', `result_${script_name}` + download_extension);

		document.body.appendChild(download_link);
		download_link.click();
		document.body.removeChild(download_link);
}

function add_buttons () {
	let border_left = document.getElementById("webscripts_border_left");
	
	let index_button = document.createElement("button");
	let console_button = document.createElement("button");
	let history_button = document.createElement("button");
	let download_button = document.createElement("button");

	index_button.innerText = "Index";
	console_button.innerText = "Clear outputs";
	history_button.innerText = "Clear history";
	download_button.innerText = "Download";

	index_button.onclick = index_page;
	console_button.onclick = clear_console;
	history_button.onclick = clear_history;
	download_button.onclick = download;

	index_button.style.marginBottom = "5%";
	console_button.style.marginBottom = "5%";
	history_button.style.marginBottom = "5%";
	download_button.style.marginBottom = "5%";

	index_button.style.marginTop = "5%";
	console_button.style.marginTop = "5%";
	history_button.style.marginTop = "5%";
	download_button.style.marginTop = "5%";

	border_left.appendChild(index_button);
	border_left.appendChild(console_button);
	border_left.appendChild(history_button);
	border_left.appendChild(download_button);
}

function progress_bar () {
	if (progress) {
		progress = false;

		function running () {
			if (width >= 100) {
				clearInterval(interval);
				progress = true;

				if (is_running) {
					progress_bar();
				} else {
					bar.style.textAlign = "center";
					bar.innerText = "Completed.";
				}
			} else {
				width++;
				bar.style.width = width + "%";
			}
		}

		let bar = document.getElementById("bar");
		let width = 1;
		bar.innerText = "Script is running...";
		bar.style.textAlign = "left";
		bar.style.padding = "1%";
		let interval = setInterval(running, 10);
	}
}

function url_default_values () {
	let event;
	let element;
	let query = location.search;
	query = query.substr(1);
	query.split("&").forEach(function(part) {
		let item = part.split("=");

		element = document.getElementById(decodeURIComponent(item[0]));
		if (element) {
			element.value = decodeURIComponent(item[1]);
			event = new Event('change');
			element.dispatchEvent(event);
		}
	});
}
