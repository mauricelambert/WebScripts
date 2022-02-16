/*

        Scripts for script.html
        Copyright (C) 2021  Maurice Lambert

        This program is free software: you can redistribute it and/or modify
        it under the terms of the GNU General Public License as published by
        the Free Software Foundation, either version 3 of the License, or
        (at your option) any later version.

        This program is distributed in the hope that it will be useful,
        but WITHOUT ANY WARRANTY; without even the implied warranty of
        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    See the
        GNU General Public License for more details.

        You should have received a copy of the GNU General Public License
        along with this program.    If not, see <https://www.gnu.org/licenses/>.

*/
let script_name;
let script;
let download_extension = ".txt";
let download_text = "";
let download_type = "plain";
let download_separator = "\n";
let execution_number = 0;
let progress = true;
let is_running = false;

function build_script_interface(scripts) {

    function add_description(script) {
        document.getElementById("script_description").innerText = script
            .description;
    }

    function add_arguments(script) {

        function set_custom_attributes(argument, config) {
            attributes = config.javascript_attributs;

            for (let attribute in attributes) {
                argument.setAttribute(attribute, attributes[attribute]);
            }
        }

        function config_advanced_arguments(advanced_container,
            advanced_arguments) {
            if (!advanced_container.getElementsByClassName("row").length) {
                advanced_container.style.display = "none";
            } else {
                let button = document.getElementById("print_advanced");
                button.onclick = () => {
                    if (advanced_arguments.style.display &&
                        advanced_arguments.style.display !== "none") {
                        advanced_arguments.style.display = "none";
                        button.innerText = "Show advanced arguments";
                    } else {
                        advanced_arguments.style.display = "block";
                        button.innerText = "Hide advanced arguments";
                    }
                };
            }
        }

        function add_div_row(label, paragraph, input_wrapper) {
            let div = document.createElement("div");
            div.classList.add("row");
            div.appendChild(label);
            div.appendChild(paragraph);
            div.appendChild(input_wrapper);
            return div;
        }

        function add_paragraph() {
            let paragraph = document.createElement("p");
            paragraph.classList.add("inline");
            paragraph.classList.add("description");
            paragraph.classList.add("script_presentation");
            return paragraph;
        }

        function add_label(argument) {
            let label = document.createElement("label");
            label.htmlFor = argument.name;
            label.innerText = argument.name + " :";
            label.classList.add("inline");
            label.classList.add("script_presentation");
            return label;
        }

        function add_argument_select(argument) {
            let option;
            let select = document.createElement("select");
            select.id = argument.name;
            select.name = argument.name;

            if (argument.list) {
                select.multiple = true;
            }

            if (argument.default_value !== undefined && argument
                .default_value !== null) {
                select.value = argument.default_value;
            }

            for (let i = 0; i < argument.predefined_values.length; ++i) {
                option = document.createElement("option");
                option.innerText = argument.predefined_values[i];
                option.value = argument.predefined_values[i];

                select.appendChild(option);
            }

            return select;
        }

        function get_input(arg) {
            let input = document.createElement("input");
            input.id = arg.name;
            input.name = arg.name;
            input.type = arg.html_type;

            if (arg.default_value !== undefined && arg.default_value !== null) {
                input.value = arg.default_value;
            }
            if (arg.example !== undefined && arg.example !== null) {
                input.placeholder = arg.example;
            }
            if (arg.list) {
                input.id = input.name + document.getElementsByName(
                    input.name
                ).length;
                input.onchange = input_list;
            }

            return input;
        }

        function input_list(event) {
            let source = event.target || event.srcElement;

            let next_id = source.id.substring(0, source.id.length - 1) + (
                parseInt(source.id[source.id.length - 1]) + 1);
            let next = document.getElementById(next_id);

            if (source.value === "" && (next !== null || next.value === "")) {
                next.remove();
            } else if (source.value !== "" && next === null) {
                new_element = source.cloneNode();
                new_element.id = source.name + document.getElementsByName(source
                    .name).length;
                source.parentNode.appendChild(new_element);
                new_element.onchange = input_list;
                new_element.value = "";
            }
        }

        function url_default_values() {
            let event;
            let element;
            let query = location.search;
            query = query.substr(1);
            query.split("&").forEach(function(part) {
                let item = part.split("=");
                element = decodeURIComponent(item[0]);

                if (element) {
                    element = document.getElementById(element);
                }

                if (element) {
                    element.value = decodeURIComponent(item[1]);
                    event = new Event('change');
                    element.dispatchEvent(event);
                }

            });
        }

        let arg;
        let argument;
        let div;
        let label;
        let paragraph;

        let advanced_container = document.getElementById("advanced_container");
        let advanced_arguments = document.getElementById("advanced_arguments");
        let script_interface = document.getElementById("script_interface");
        let input_wrapper;

        for (let i = 0; i < script.args.length; ++i) {
            arg = script.args[i];
            input_wrapper = document.createElement("div");
            input_wrapper.classList.add("input_wrapper");

            if (arg.predefined_values !== undefined && arg.predefined_values !==
                null) {
                argument = add_argument_select(arg);
            } else {
                argument = get_input(arg);
            }
            set_custom_attributes(argument, arg);

            input_wrapper.appendChild(argument);
            label = add_label(argument);
            paragraph = add_paragraph();

            if (arg.description !== undefined && arg.description !== null) {
                paragraph.innerText = arg.description;
            }

            input_wrapper.classList.add("inline");
            div = add_div_row(label, paragraph, input_wrapper);

            if (arg.is_advanced) {
                advanced_arguments.appendChild(div);
            } else {
                script_interface.insertBefore(div, advanced_container);
            }
        }

        add_button();
        url_default_values();
        config_advanced_arguments(advanced_container, advanced_arguments);
    }

    script = scripts[script_name];

    add_description(script);
    add_arguments(script);
}

function start_script_execution(event) {
    function get_arguments() {

        let counter = 0;
        let values = Array.from(document.getElementsByTagName('input')).concat(
            Array.from(document.getElementsByTagName('select')));
        let script_interface = document.getElementById('script_interface');
        let arguments_ = {};

        add_arguments(values, counter, arguments_);
    }

    get_arguments();
}

function sort_arguments(arguments_) {
    let send_object = {};
    let sort = [];

    for (argument in arguments_) {
        sort.push([argument, arguments_[argument]["position"]]);
    }

    sort.sort(function(a, b) {
        return a[1] - b[1];
    });

    for (argument in sort) {
        argument = sort[argument][0];
        send_object[argument] = {};
        send_object[argument]["value"] = arguments_[argument]["value"];
        send_object[argument]["input"] = arguments_[argument]["input"];
    }

    return send_object;
}

function add_value_for_request(arguments_, script_interface, id, name, value,
    values, counter) {
    if (arguments_[name] !== undefined) {
        if (!Array.isArray(arguments_[name]["value"])) {
            arguments_[name]["value"] = [arguments_[name]["value"]];
        }

        if (value) {
            arguments_[name]["value"].push(value);
        }
    } else {
        arguments_[name] = {
            "value": value,
            "position": script_interface.innerHTML.indexOf(`id="${id}"`)
        };

        let arg;
        for (let i = 0; i < script.args.length; ++i) {
            arg = script.args[i];

            if (arg.name !== name) {
                continue;
            }

            if (arg.input === true) {
                arguments_[name]["input"] = true;
                break;
            } else {
                arguments_[name]["input"] = false;
                break;
            }
        }
    }

    add_arguments(values, counter, arguments_);
}

function add_arguments(values, counter, arguments_) {

    function make_json_request(arguments_) {
        let csrf = document.getElementById("csrf_token");
        send_requests(JSON.stringify({
            "csrf_token": csrf.value,
            "arguments": arguments_,
        }));
    }

    if (counter < values.length) {
        let value = values[counter];
        counter++;
        window[`add_${value.tagName}_argument`](value, values, counter,
            arguments_);
    } else {
        arguments_ = sort_arguments(arguments_);
        make_json_request(arguments_);
        document.getElementById("submit_button").disabled = true;
        return;
    }
}

function add_NULL_argument() {}


function add_INPUT_argument(input, values, counter, arguments_) {

    if (input.type === "submit" || input.name === "csrf_token") {
        add_arguments(values, counter, arguments_);
        return;
    }

    if (input.type === "checkbox") {
        add_value_for_request(
            arguments_,
            script_interface,
            input.id,
            input.name,
            input.checked,
            values,
            counter,
        );
    } else if (input.type === "file") {
        let reader = new FileReader();

        reader.onload = (a) => {
            add_value_for_request(
                arguments_,
                script_interface,
                input.id,
                input.name,
                window.btoa(a.target.result),
                values,
                counter,
            );
        };

        if (input.files.length) {
            reader.readAsBinaryString(input.files[0]);
        } else {
            add_arguments(values, counter, arguments_);
        }
    } else {
        add_value_for_request(
            arguments_,
            script_interface,
            input.id,
            input.name,
            input.value,
            values,
            counter,
        );
    }
}

function add_SELECT_argument(select, values, counter, arguments_) {
    let selected = [];
    let first = true;

    for (let l = 0; l < select.options.length; ++l) {
        option = select.options[l];

        if (option.selected) {
            selected.push(option.value);
            if (first) {
                first = false;
            } else {
                values.push({
                    "tagName": "NULL"
                });
            }
        }
    }

    selected.forEach((item) => {
        add_value_for_request(
            arguments_,
            script_interface,
            select.id,
            select.name,
            item,
            values,
            counter++,
        );
    });

    return arguments_;
}


function send_requests(json, first = true) {
    let xhttp = new XMLHttpRequest();
    let start;
    let full_output = "";
    let full_error = "";

    function post_execute_script() {
        let url;
        if (script_name[0] === "/") {
            url = script_name;
        } else {
            url = "/api/scripts/" + script_name;
        }

        xhttp.open("POST", url, true);
        xhttp.setRequestHeader('Content-Type', 'application/json');
        xhttp.send(json);
        start = Date.now();

        is_running = true;
        progress_bar();
    }

    function get_new_line(response) {
        xhttp.open('GET', `/api/script/get/${response.key}`, true);
        xhttp.send()
    }

    function prepare_output() {
        let end = Date.now();
        let response_object = JSON.parse(xhttp.responseText);

        if (response_object.csrf) {
            document.getElementById("csrf_token").value = response_object
                .csrf;
        }

        if (response_object.key) {
            if (!response_object.code) {
                response_object.code = "Running...";
            }
            if (!response_object.error) {
                response_object.error = "Running...";
            }

            if (build_output_interface(
                    response_object,
                    add_history_ = false,
                    time = "Running...",
                    make_new_output = first,
                )) {
                first = false;
            };

            full_output += response_object.stdout;
            full_error += response_object.stderr;
            get_new_line(response_object);

            return;
        }

        diff_seconds = Math.round((end.valueOf() - start.valueOf()) /
            1000);
        minutes = Math.round(diff_seconds / 60);
        seconds = diff_seconds - minutes * 60;

        if (minutes < 10) {
            minutes = `0${minutes}`;
        }
        if (seconds < 10) {
            seconds = `0${seconds}`;
        }

        build_output_interface(
            response_object,
            add_history_ = true,
            time = `${minutes}:${seconds}`,
            make_new_output = false,
            update = true,
            full_output = full_output,
            full_error = full_error,
        );

        document.getElementById("submit_button").disabled = false;
        is_running = false;
        first = true;
        document.getElementById('code').id = `last_code_${execution_number}`;
        document.getElementById('last_output').id = `last_output_${execution_number}`;
        document.getElementById('console').id = `console_${execution_number}`;
    }

    xhttp.onreadystatechange = () => {
        let class_link = "";

        if (localStorage.getItem('theme') === "light" || window.matchMedia(
                "(prefers-color-scheme: light)").matches) {
            class_link = 'class="light" ';
        }

        if (xhttp.readyState === 4 && xhttp.status === 200) {
            prepare_output(xhttp);
        } else if (xhttp.readyState === 4 && xhttp.status === 302 &&
            script_name === "/auth/") {

            if (document.referrer && document.referrer.startsWith(window
                    .location.origin) && !document.referrer.endsWith(
                    "/web/auth/")) {
                window.location = document.referrer;
            } else {
                window.location = new URL("/web/", window.location);
            }

        } else if (xhttp.readyState === 4 && xhttp.status === 500) {
            document.getElementById("bar").innerHTML =
                `ERROR 500: Internal Server Error. \nYou can report a bug` +
                ` <a ${class_link}href="/error_pages/Report/new/` +
                `${xhttp.status}">on the local report page</a>.`;

            document.getElementById("submit_button").disabled = false;
            is_running = false;
        } else if (xhttp.readyState === 4 && xhttp.status === 403) {
            document.getElementById("bar").innerHTML =
                `ERROR 403: Forbidden. (Refresh the page or re-authenticate ` +
                `please). \nYou can <a ${class_link}href="/error_pages/Report/new` +
                `/${xhttp.status}">request access to the administrator</a>.`;

            document.getElementById("submit_button").disabled = false;
            is_running = false;
        } else if (xhttp.readyState === 4) {
            document.getElementById("bar").innerHTML =
                `HTTP ERROR ${xhttp.status}. \nYou can report a bug <a ` +
                `${class_link}href="/error_pages/Report/new/${xhttp.status}"` +
                `>on the local report page</a>.`;

            document.getElementById("submit_button").disabled = false;
            is_running = false;
        }
    }

    post_execute_script();
}

function build_output_interface(output, add_history_ = true, time = null, make_new_output = true, update = false, full_output = null, full_error = null) {

    function clean_string(string) {
        return string.replace(/^\s+|\s+$/g, '');
    };

    function build_code(output, time) {
        let code = document.createElement("code");
        code.id = "code";
        code.classList.add("code");

        code.innerText =
            `>>> ${script_name}    ExitCode: ${output.code}    Error: ${output.error}`;

        if (time) {
            code.innerText += `    ExecutionTime: ${time}`;
        }

        return code;
    }

    function build_new_output(code) {
        let new_output = document.createElement("div");
        let console_ = document.createElement("pre");

        new_output.id = "last_output";

        console_.id = "console";
        console_.classList.add("console");

        console_.appendChild(code);
        new_output.appendChild(console_);

        make_new_output = true;

        return new_output;
    }

    const unescape = str => str.replace(/&lt;/g, '<').replace(/&gt;/g, '>')
        .replace(/&#x27;/g, "'").replace(/&quot;/g, '"').replace(/&amp;/g, '&');
    const universal_new_line = str => str.replace(/\r\n/g, "\n");

    let console_div = document.getElementById("script_outputs");
    let content_type = output["Content-Type"];
    let stderr_content_type;
    let text = "";
    let html = "";
    let code;
    let new_output;

    let error_string = clean_string(output.stderr);
    let output_string = clean_string(output.stdout);

    if (make_new_output) {
        code = build_code(output, time);
        new_output = build_new_output(code);
    } else {
        code = document.getElementById("code") || build_code(output, time);
        new_output = document.getElementById("last_output") || build_new_output(code);
    }

    if (update) {
        code.innerText = code.innerText.replace('Running...', output.code).replace('Running...', output.error).replace('Running...', time);
    }

    if (add_history_) {
        add_history(
            full_output || output.stdout,
            full_error || output.stderr,
            output.code,
            output.error,
            content_type,
            stderr_content_type,
            time,
        );
    }

    if ((output_string + error_string).length === 0) {
        return false;
    }

    if (output.hasOwnProperty("Stderr-Content-Type")) {
        stderr_content_type = output["Stderr-Content-Type"];
    } else {
        stderr_content_type = "text/plain";
    }

    if (error_string.length !== 0) {
        if (stderr_content_type.includes("text/html")) {
            html += output.stderr;
        } else {
            text += `\n${output.stderr}`;
        }
    }

    if (content_type.includes("text/html")) {
        download_extension = ".html";
        download_separator = "\n<br>\n";
        download_type = "html";
        html = output.stdout + html;
    } else {
        download_extension = ".txt";
        download_separator = "\n";
        download_type = "plain";

        if (make_new_output) {
            text = `\n${output.stdout}${text}`;
        } else {
            text = `${output.stdout}${text}`;
        }
    }

    code.innerText += universal_new_line(unescape(text));
    new_output.innerHTML += html;

    console_div.appendChild(new_output);
    download_text += `${text}\n${html}${download_separator}`;

    if (localStorage.getItem('theme') === "light") {
        change_theme(class_name = 'light', element = new_output);
    }
    /* else if (localStorage.getItem('theme') === null) {
            change_theme(class_name = 'default_theme', element = new_output);
        }*/
    return true;
}

function add_history(stdout, stderr, code, error, content_type,
    stderr_content_type, time) {
    let button = document.createElement("button");
    button.onclick = build_output_interface.bind(
        button, {
            'stdout': stdout,
            'stderr': stderr,
            'code': code,
            'error': error,
            'Content-Type': content_type,
            'Stderr-Content-Type': stderr_content_type,
        },
        add_history_=false,
        time=time,
    );
    button.innerText = execution_number;
    execution_number++;
    document.getElementById("webscripts_border_right").appendChild(button);

    if (localStorage.getItem('theme') === "light") {
        button.classList.toggle("light");
    } else if (localStorage.getItem('theme') === null) {
        button.classList.toggle("default_theme");
    }
}


function clear_console() {
    document.getElementById("script_outputs").innerText = "";
    download_text = "";
}

function clear_history() {
    execution_number = 0;
    document.getElementById("webscripts_border_right").innerText = "";
}

function index_page() {
    window.location = new URL("/web/", window.location);
}

function download() {
    let download_link = document.createElement('a');
    download_link.setAttribute('href',
        `data:text/${download_type};charset=utf-8,` + encodeURIComponent(
            download_text));
    download_link.setAttribute('download', `result_${script_name}` +
        download_extension);

    document.body.appendChild(download_link);
    download_link.click();
    document.body.removeChild(download_link);
}

function add_buttons() {
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

function progress_bar() {
    if (progress) {
        progress = false;

        function running() {
            if (width >= 97) {
                clearInterval(interval);
                progress = true;

                if (is_running) {
                    progress_bar();
                } else {
                    bar.style.textAlign = "center";

                    if (bar.innerText == "Script is running...") {
                        bar.innerText = "Completed.";
                    }
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
        let interval = setInterval(running, 20);
    }
}