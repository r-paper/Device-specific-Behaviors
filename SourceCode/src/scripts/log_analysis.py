import os
import hashlib
import json
import copy
import pickle

from tqdm import tqdm


log_path = ""
rule_path = ""
splitor = "-------------------------------------------------\n"


# global variable
rule_arr = []
accepted_sources = ["android.os.Build: java.lang.String BRAND", "android.os.Build: java.lang.String DEVICE", "android.os.Build: java.lang.String DISPLAY", "android.os.Build: java.lang.String FINGERPRINT", "android.os.Build: java.lang.String MANUFACTURER", "android.os.Build: java.lang.String MODEL", "android.os.Build: java.lang.String PRODUCT", "SystemProperties"]

accepted_sources_2 = ["android.os.Build: java.lang.String BRAND", "android.os.Build: java.lang.String DEVICE", "android.os.Build: java.lang.String DISPLAY", "android.os.Build: java.lang.String FINGERPRINT", "android.os.Build: java.lang.String MANUFACTURER", "android.os.Build: java.lang.String MODEL", "android.os.Build: java.lang.String PRODUCT", "<java.lang.Class: java.lang.Class forName(java.lang.String)>(\"android.os.SystemProperties\")"]

accepted_parameter_function = ["java.util.regex.Pattern: java.util.regex.Matcher matcher(java.lang.CharSequence)"]

brand_list_path = ""
os_list_path = ""
model_list_path = ""

brand_list = []
os_list = []
model_list = []


class DirectedGraph:
    def __init__(self):
        self.graph = {}


    def add_vertex(self, vertex):
        if vertex not in self.graph:
            self.graph[vertex] = []


    def add_edge(self, start, end):
        if start in self.graph:
            self.graph[start].append(end)
        else:
            raise ValueError(f"Vertex {start} does not exist in the graph.")


    def get_in_neighbors(self, vertex):
        if vertex in self.graph:
            return self.graph[vertex]
        else:
            raise ValueError(f"Vertex {vertex} does not exist in the graph.")
        

    def get_out_neighbors(self, vertex):
        if vertex in self.graph:
            out_neighbors = []
            for source_vertex in self.graph:
                if vertex in self.graph[source_vertex]:
                    out_neighbors.append(source_vertex)
            return out_neighbors
        else:
            raise ValueError(f"Vertex {vertex} does not exist in the graph.")

    
    def get_graph(self):
        return self.graph
    

    def dfs(self, start, visited):
        visited.add(start)
        for neighbor in self.graph[start]:
            if neighbor not in visited:
                self.dfs(neighbor, visited)

    
    def find_connected_components(self):
        visited = set()
        connected_components = []
        for vertex in self.graph:
            if vertex not in visited:
                component = set()
                self.dfs(vertex, component)
                # connected_components = DirectedGraph.merge_collections(connected_components, component)
                connected_components.append(component)
                visited.update(component)
        return DirectedGraph.merge_intersecting_sets(connected_components)


    def has_vertex(self, vertex):
        return vertex in self.graph


    def has_edge(self, start, end):
        if start in self.graph:
            return end in self.graph[start]
        else:
            return False


    @staticmethod
    def merge_collections(collection_array, collection_to_merge):
        for coll in collection_array:
            if coll.intersection(collection_to_merge):
                coll.update(collection_to_merge)
                return collection_array
        
        collection_array.append(collection_to_merge)
        return collection_array


    @staticmethod
    def merge_intersecting_sets(sets):
        merged_sets = sets.copy()

        def find_intersection():
            for i in range(len(merged_sets)):
                for j in range(i + 1, len(merged_sets)):
                    if merged_sets[i].intersection(merged_sets[j]):
                        return i, j
            return None

        intersection = find_intersection()
        while intersection is not None:
            i, j = intersection
            merged_sets[i].update(merged_sets[j])
            del merged_sets[j]
            intersection = find_intersection()

        return merged_sets


def find_files(base_path):
    results = []
    file_list = os.listdir(base_path)
    for file in file_list:
        cur_path = os.path.join(base_path, file)
        if not os.path.isdir(cur_path):
            results.append(cur_path)
    return results


def calculate_md5(input_string):
    md5_hash = hashlib.md5()
    md5_hash.update(input_string.encode('utf-8'))
    return md5_hash.hexdigest()


def merge_array(array):
    result = ""
    for i in sorted(array):
        result += str(i)
    return result


def generate_source_line(source_dict):
    source_line = ""
    for func in source_dict:
        for source in source_dict[func]:
            if source_line == "":
                source_line += source + " in " + func
            else:
                source_line += "\n" + source + " in " + func
    return source_line


def load_rules():
    with open(rule_path, "r") as rule_file:
        for line in rule_file.readlines():
            rule_arr.append(json.loads(line.strip()))


def is_keyword_in_content(keyword_a, content_a):
    is_found = False
    keyword = keyword_a.lower()
    content = content_a.lower()

    if keyword in content:
        is_found = True
    if " " in keyword:
        if keyword.replace(" ", "") in content:
            is_found = True
        if keyword.replace(" ", "_") in content:
            is_found = True
    return is_found


def classify(function_body):
    result = []
    for rule_item in rule_arr:
        for rule in rule_item["rule_list"]:
            if rule["matching_method"] == "match":
                is_found = is_keyword_in_content(rule["keyword"], function_body)
                if is_found:
                    if rule["keyword"] == "short cut":
                        if is_keyword_in_content("short cut badge", function_body):
                            continue
                    result_item = copy.deepcopy(rule)
                    result_item["class"] = rule_item["classification"]
                    result.append(result_item)
            elif rule["matching_method"].startswith("morethan"):
                threshold = int(rule["matching_method"].split("_")[-1])
                match_time = 0
                for keyword in rule["keyword"]:
                    is_found = is_keyword_in_content(keyword, function_body)
                    if is_found:
                        match_time += 1
                if match_time >= threshold:
                    result_item = copy.deepcopy(rule)
                    result_item["class"] = rule_item["classification"]
                    result.append(result_item)
            elif rule["matching_method"] == "match_all":
                is_match_all = True
                for keyword in rule["keyword"]:
                    is_found = is_keyword_in_content(keyword, function_body)
                    if not is_found:
                        is_match_all = False
                if is_match_all:
                    result_item = copy.deepcopy(rule)
                    result_item["class"] = rule_item["classification"]
                    result.append(result_item)
    return result


def rule_to_string(rule):
    result = ""
    result += rule["class"] + " - " + rule["priority"] + " - " + " - " + str(rule["keyword"])
    return result


def is_library_method(method_name):
    return (method_name.startswith("java.") or
            method_name.startswith("sun.") or
            method_name.startswith("javax.") or
            method_name.startswith("com.sun.") or
            method_name.startswith("org.omg.") or
            method_name.startswith("org.xml.") or
            method_name.startswith("org.w3c") or
            method_name.startswith("androidx.") or
            method_name.startswith("android.") or 
            method_name.startswith("com.android") or 
            method_name.startswith("dalvik") or 
            method_name.startswith("org.apache") or
            method_name.startswith("kotlin") or
            method_name.startswith("kotlin"))


def cluster():
    dup = set()
    total_method_num = 0

    log_path = ""
    
    file_paths = find_files(log_path)

    for file_path in file_paths:
        # load file content
        with open(file_path, "r", encoding="utf-8") as file:
            is_headline = True
            summary = {}
            headline = ""
            content = ""
            invoke_link = []
            for line in file.readlines():
                # process for special line
                if line == "--------------------ResultBuild--------------------\n":
                    continue
                if line == "--------------------ResultReflection--------------------\n":
                    continue
                if line == "--------------------Dangerous--------------------\n" or line == "--------------------FurtherAnalysis--------------------\n":
                    # write last code block
                    if content == "":
                        break
                    summary[headline]["content"] = content
                    summary[headline]["invoke_link"] = invoke_link

                    break
                if line == splitor:
                    # write previous code block first
                    if content == "":
                        continue
                    if headline not in summary:
                        print("Logic error in headline")
                    else:
                        summary[headline]["content"] = content
                        summary[headline]["invoke_link"] = invoke_link
                                
                    # new code block
                    is_headline = True
                    content = ""
                    invoke_link = []
                else:
                    # process headline
                    if is_headline:
                        start_index = line.find("<") + 1
                        end_index = line.rfind(">")
                        headline = line[start_index: end_index]
                        summary[headline] = {}
                        is_headline = False
                    else:
                        content += line
                        # process invoke link
                        if "invoke" in line:
                            start_index = line.find("<", line.find("invoke")) + 1
                            end_index = line.rfind(")>(") + 1
                            function_name = line[start_index: end_index]
                            if is_library_method(function_name):
                                invoke_link.append(function_name)
        
            # end of file
            if headline in summary and ("invoke_link" not in summary[headline] or "content" not in summary[headline]):
                summary[headline]["content"] = content
                summary[headline]["invoke_link"] = invoke_link


def identify_if_hit():
    log_path = ""

    report_path = ""
    
    file_paths = find_files(log_path1)

    load_rules()
    load_device_info_list()

    hit_result = []

    success = 0
    total = 0

    # process per file
    for file_path in tqdm(file_paths):
        file_result = []
        # load file content
        with open(file_path, "r", encoding="utf-8") as file:
            is_headline = True
            summary = {}
            headline = ""
            content = ""
            invoke_link = []
            for line in file.readlines():
                # process for special line
                if line == "--------------------ResultBuild--------------------\n":
                    continue
                if line == "--------------------ResultReflection--------------------\n":
                    continue
                if line == "--------------------Dangerous--------------------\n" or line == "--------------------FurtherAnalysis--------------------\n":
                    # write last code block
                    if content == "":
                        break
                    if headline not in summary:
                        print("Logic error in headline")
                    else:
                        summary[headline]["content"] = content
                        summary[headline]["invoke_link"] = invoke_link
                    break
                if line == splitor:
                    # write previous code block first
                    if content == "":
                        continue
                    if headline not in summary:
                        print("Logic error in headline")
                    else:
                        summary[headline]["content"] = content
                        summary[headline]["invoke_link"] = invoke_link
                                
                    # new code block
                    is_headline = True
                    content = ""
                    invoke_link = []
                else:
                    # process headline
                    if is_headline:
                        start_index = line.find("<") + 1
                        end_index = line.rfind(">")
                        headline = line[start_index: end_index]
                        summary[headline] = {}
                        is_headline = False
                    else:
                        content += line
                        # process invoke link
                        if "invoke" in line:
                            start_index = line.find("<", line.find("invoke")) + 1
                            end_index = line.rfind(")>(") + 1
                            function_name = line[start_index: end_index]
                            invoke_link.append(function_name)
        
            # end of file
            if headline in summary and ("invoke_link" not in summary[headline] or "content" not in summary[headline]):
                summary[headline]["content"] = content
                summary[headline]["invoke_link"] = invoke_link
        # end - load file content

        # check if the file is empty
        if len(summary) == 0:
            continue

        # call link
        call_graph = DirectedGraph()
        for func in summary:
            call_graph.add_vertex(func)
            for called_func in summary[func]["invoke_link"]:
                if called_func in summary:
                    call_graph.add_edge(func, called_func)
        components = call_graph.find_connected_components()

        # output & duplication in componenet level
        for component in components:
            source = {}
            for func in component:
                temp_source = set()
                for content in summary[func]["content"].split('\n'):
                    if "android.os.Build" in content:
                        start_index = content.rfind("<")
                        end_index = content.rfind(">") + 1
                        build_prop = content[start_index: end_index]
                        temp_source.add(build_prop)
                    if "android.os.SystemProperties" in content:
                        temp_source.add("SystemProperties")
                if len(temp_source) > 0:
                    source[func] = temp_source
            # source line
            if len(source) == 0:
                continue
            source_line = generate_source_line(source)

            # judge skip after remove unaccepted source
            is_skip = True
            for accepted_source in accepted_sources:
                if accepted_source in source_line:
                    is_skip = False
                    break
            if is_skip:
                continue
            
            # add more logic for source method
            # for_sure_result = component
            for_sure_result = {}
            for func in source:
                visited_function = []
                taint_analyze(summary, call_graph, func, accepted_sources_2, for_sure_result, False, visited_function)
            if len(for_sure_result) > 0:
                file_result.append(for_sure_result)

        # the end of the analysis of a file
        if len(file_result) > 0:
            file_dict = {}
            file_dict["file_path"] = file_path
            file_dict["components"] = []
            hit_result.append(file_dict)
            for component in file_result:
                total += 1
                device_info_flag = False
                hit_flag = False
                component_arr = []
                for function_name in component:
                    function_dict = {}
                    component_arr.append(function_dict)

                    function_dict["function_name"] = function_name
                    function_dict["body"] = component[function_name]

                    brand_in_name = is_brand_in_content(function_name, 1)
                    os_in_name = is_os_in_content(function_name, 1)
                    model_in_name = is_model_in_content(function_name, 1)

                    brand_in_body = is_brand_in_content(merge_array(component[function_name]), 1)
                    os_in_body = is_os_in_content(merge_array(component[function_name]), 1)
                    model_in_body = is_model_in_content(merge_array(component[function_name]), 1)

                    if len(brand_in_name) > 0 or len(os_in_name) > 0 or len(model_in_name) > 0 or len(brand_in_body) > 0 or len(os_in_body) > 0 or len(model_in_body) > 0:
                        device_info_flag = True

                    if len(brand_in_name) > 0:
                        function_dict["brand_in_name"] = brand_in_name
                    if len(os_in_name) > 0:
                        function_dict["os_in_name"] = os_in_name
                    if len(model_in_name) > 0:
                        function_dict["model_in_name"] = model_in_name
                    
                    if len(brand_in_body) > 0:
                        function_dict["brand_in_body"] = brand_in_body
                    if len(os_in_body) > 0:
                        function_dict["os_in_body"] = os_in_body
                    if len(model_in_body) > 0:
                        function_dict["model_in_body"] = model_in_body
                    
                    # classify
                    matching_rules = classify(function_name + merge_array(component[function_name]))
                    if len(matching_rules) > 0:
                        hit_flag = True
                        function_dict["matching_rules"] = []
                        for matching_rule in matching_rules:
                            function_dict["matching_rules"].append(matching_rule)

                if device_info_flag:
                    total += 1
                    if hit_flag:
                        success += 1
                        file_dict["components"].append(component_arr)

    with open(report_path, "wb") as file:
        pickle.dump(hit_result, file, protocol=5)


def taint_analyze(summary, call_graph, func, accepted_sources, for_sure_result, is_return, visited_functions):
    if func in visited_functions:
        return
    visited_functions.append(func)

    return_start_index = func.find(": ") + 2
    return_end_index = func.find(" ", return_start_index)
    return_type = func[return_start_index: return_end_index]

    source_vars = set()
    cur_line_num = 0
    for line in summary[func]["content"].split("\n"):
        cur_line_num += 1
        # find source var first
        if accepted_source_in_line(line, accepted_sources) and "=" in line and "goto" not in line:
            source_vars.add(line.split(" = ")[0])
            continue
        
        # find use
        if len(source_vars) and len(source_var_in_line(source_vars, line)):
            # source var killed
            for occurred_var in source_var_in_line(source_vars, line):
                if line.startswith(occurred_var + " = "):
                    source_vars.remove(occurred_var)
            
            # use case
            if line.startswith("if "):
                first_op, condition, second_op, condition_str, goto_str = get_if_statement_op(line)
                for occurred_var in source_var_in_line(source_vars, condition_str):
                    if occurred_var == first_op or occurred_var == second_op:
                        if_body = get_if_body(summary[func]["content"], cur_line_num, goto_str, False)
                        if func not in for_sure_result:
                            if is_return:
                                for_sure_result[func] = [source_vars_to_string(accepted_sources)] + summary[func]["content"].split("\n")
                            else:
                                for_sure_result[func] = summary[func]["content"].split("\n")
                        for if_stmt in if_body:
                            if "invoke" in if_stmt and "goto" not in if_stmt:
                                function_start_index = if_stmt.find("<", if_stmt.find("invoke")) + 1
                                function_end_index = if_stmt.rfind(")>(") + 1
                                function_name = if_stmt[function_start_index: function_end_index]
                                if function_name in summary and function_name not in for_sure_result:
                                    for_sure_result[function_name] = ["Sub function of " + func] + summary[function_name]["content"].split("\n")
                                    retrieve_callee_in_function(function_name, for_sure_result, summary)
                            if is_return_statement(if_stmt):
                                callee_functions = call_graph.get_out_neighbors(func)
                                if len(callee_functions) > 0 and "Return in taint if body" not in for_sure_result[func]:
                                    for_sure_result[func] = ["Return in taint if body"] + for_sure_result[func]
                                    for callee_function in callee_functions:
                                        source_arg = []
                                        source_arg.append(func)
                                        taint_analyze(summary, call_graph, callee_function, source_arg, for_sure_result, True, visited_functions)
            elif return_type != "void" and line.startswith("return "):
                return_op = line.split(" ")[-1]
                if return_op in source_vars:
                    if func == "com.umeng.commonsdk.utils.UMUtils: java.lang.String getSystemProperty(java.lang.String,java.lang.String)":
                        pass

                    callee_functions = call_graph.get_out_neighbors(func)
                    if len(callee_functions) > 0:
                        for_sure_result[func] = ["Taint return value"] + summary[func]["content"].split("\n") 
                        for callee_function in callee_functions:
                            if callee_function == "com.mob.commons.authorize.a: boolean a(java.util.HashMap)":
                                pass
                            source_arg = []
                            source_arg.append(func)
                            taint_analyze(summary, call_graph, callee_function, source_arg, for_sure_result, True, visited_functions)
            elif "invoke" in line and "goto" not in line:
                function_start_index = line.find("<", line.find("invoke")) + 1
                function_end_index = line.rfind(")>(") + 1
                function_name = line[function_start_index: function_end_index]

                parameter_start_index = line.rfind("(") + 1
                parameter_end_index = line.rfind(")")
                parameter_str = line[parameter_start_index: parameter_end_index]
                parameter_list = parameter_str.split(", ")
                
                for occurred_var in source_var_in_line(source_vars, line):
                    # source var call function
                    if is_assign_statement(line) and occurred_var + ".<" + function_name in line:
                        # assign 
                        left_op, right_op = get_assign_statement_op(line)
                        if occurred_var + ".<" + function_name in right_op:
                            source_vars.add(left_op)
                    # source var in parameters
                    elif occurred_var in parameter_list:
                        left_op, right_op = get_assign_statement_op(line)
                        if function_name in accepted_parameter_function or function_name.startswith("java.lang.String"):
                            source_vars.add(left_op)
            elif is_type_cast_statement(line):
                first_op, second_op = get_type_cast_statement_op(line)
                if second_op in source_vars:
                    source_vars.add(first_op)


def retrieve_callee_in_function(function_name, for_sure_result, summary):
    for line in summary[function_name]["content"].split("\n"):
        if "invoke" in line and "goto" not in line:
            function_start_index = line.find("<", line.find("invoke")) + 1
            function_end_index = line.rfind(")>(") + 1
            sub_function_name = line[function_start_index: function_end_index]
            if sub_function_name in summary and sub_function_name not in for_sure_result:
                for_sure_result[sub_function_name] = ["Sub function of " + function_name] + summary[sub_function_name]["content"].split("\n")
                retrieve_callee_in_function(sub_function_name, for_sure_result, summary)


def is_brand_in_content(content, mode):
    result = []
    content = content.lower()

    for brand in brand_list:
        brand = brand.lower()
        if mode == 1:
            if brand in ["blu", "bq", "cat", "lg", "nec", "niu", "yu"]:
                continue
        if brand in content:
            result.append(brand)

    return result


def is_os_in_content(content, mode):
    result = []
    content = content.lower()

    for os_name in os_list:
        os_name = os_name.lower()

        if mode == 1 and os_name in ["xos", "xui", "zui", "eui"]:
            continue

        if mode == 2:
            if content == os_name:
                result.append(os_name)
                continue

            if " " in os_name:
                if content == os_name.replace(" ", ""):
                    result.append(os_name)
                    continue
                if content == os_name.replace(" ", "_"):
                    result.append(os_name)
                    continue
        else:
            if os_name in content:
                result.append(os_name)
                continue

            if " " in os_name:
                if os_name.replace(" ", "") in content:
                    result.append(os_name)
                    continue
                if os_name.replace(" ", "_") in content:
                    result.append(os_name)
                    continue

    return result


def is_model_in_content(content, mode):
    result = []
    content = content.lower()

    for model in model_list:
        model = model.lower()

        if mode in [1, 2] and len(model) < 4:
            continue

        if mode == 2:
            if model == content:
                result.append(model)
        else:
            if model in content:
                result.append(model)

    return result


def load_device_info_list():
    with open(brand_list_path, "r") as file:
        for line in file.readlines():
            if line.strip() == "":
                pass
            brand_list.append(line.strip())
    
    with open(os_list_path, "r") as file:
        for line in file.readlines():
            if line.strip() == "":
                pass
            os_list.append(line.strip())

    with open(model_list_path, "r") as file:
        for line in file.readlines():
            if line.strip() == "":
                pass
            model_list.append(line.strip())


def source_vars_to_string(source_vars):
    result_str = "Source_var: "
    for source_var in source_vars:
        result_str += source_var
    return result_str


def get_if_body(function_body, if_line_num, goto_str, is_twisted):    
    line_num = 0
    if_body = []

    if is_twisted:
        is_after_goto = False
        for temp_line in function_body.split("\n"):
            line_num += 1
            if line_num >= if_line_num + 1:
                if temp_line == goto_str:
                    is_after_goto = True
                    if_body.append(temp_line)
                    continue
                if is_after_goto:
                    if temp_line.startswith("return"):
                        if_body.append(temp_line)
                        break
                    if_body.append(temp_line)
        return if_body
    else:
        is_branch_twisted = False
        for temp_line in function_body.split("\n"):
            line_num += 1
            if line_num == if_line_num:
                first_op, condition, second_op, condition_str, goto_str = get_if_statement_op(temp_line)
                if goto_str.startswith("return"):
                    is_branch_twisted = True
            if line_num >= if_line_num + 1:
                if temp_line == goto_str and len(if_body) > 0:
                    break
                if_body.append(temp_line)
        
        line_num = if_line_num
        # compound conditional statement
        for if_stmt in if_body:
            line_num += 1
            if if_stmt.startswith("if "):
                first_op, condition, second_op, condition_str, goto_str = get_if_statement_op(if_stmt)
                temp_if_body = get_if_body(function_body, line_num, goto_str, is_branch_twisted)
                if_body.extend(temp_if_body)
                break
        return if_body


def is_type_cast_statement(line):
    if len(line.split(" ")) == 4:
        first = line.split(" ")[0]
        second = line.split(" ")[1]
        third = line.split(" ")[2]
        fourth = line.split(" ")[3]
        if first.startswith("$") and second == "=" and third.startswith("(") and third.endswith(")") and fourth.startswith("$"):
            return True
    return False


def get_type_cast_statement_op(line):
    first = line.split(" ")[0]
    fourth = line.split(" ")[3]
    return first, fourth


def accepted_source_in_line(line, accepted_sources):
    result = False
    for accepted_source in accepted_sources:
        if accepted_source in line:
            result = True
            break
    return result


def source_var_in_line(source_vars, line):
    result = set()
    for source_var in source_vars:
        if source_var in line:
            result.add(source_var)
            break
    return result


def get_assign_statement_op(statement):
    left_op = statement.split(" = ")[0]
    right_op = statement.split(" = ")[-1]
    return left_op, right_op


def get_if_statement_op(statement):
    condition_start_index = statement.find("if ") + 3
    condition_end_index = statement.find(" goto ")
    condition_str = statement[condition_start_index: condition_end_index]

    first_op = condition_str.split(" ")[0]
    condition = condition_str.split(" ")[1]
    second_op = condition_str.split(" ")[2]

    goto_str = statement[condition_end_index+6:]
    return first_op, condition, second_op, condition_str, goto_str


def is_assign_statement(statement):
    if " = " in statement and statement.startswith("$"):
        return True
    else:
        return False
    

def is_return_statement(statement):
    if statement.startswith("return "):
        return True
    return False


if __name__ == "__main__":
    identify_if_hit()
