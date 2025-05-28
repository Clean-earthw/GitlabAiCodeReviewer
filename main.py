import functions_framework
from gitlab import Gitlab
import vertexai
from vertexai.generative_models import GenerationConfig, GenerativeModel
from google.cloud import logging as gcp_logging
import json
import os
from dotenv import load_dotenv

# Load environment variables from .env file (for local development/testing)
load_dotenv()
DEBUG_MODE = os.environ.get("DEBUG_MODE")
MODEL_ID = "gemini-1.5-pro-001"

@functions_framework.http
def gitlab_gemini_webhook_handler(request):
    """
    Main entry point for handling GitLab webhook events. This function receives
    webhook payloads from GitLab, verifies their authenticity, determines the event type,
    and dispatches the appropriate handler function.

    Args:
        request: A Flask request object containing the webhook payload and headers.

    Returns:
        A string message indicating the outcome of the webhook processing, along with an HTTP status code (200 for success, 403 for invalid token, or 200 for unsupported events).

    Raises:
        N/A (Errors are logged using google.cloud.logging)
    """
    
    
    logging_client = gcp_logging.Client()
    logger = logging_client.logger("gemini-code-review-logger")
    logger.log_text("Webhook received", severity="INFO")

    """Main entry point for GitLab webhook events."""
    
    gitlab_webhook = os.environ.get('GITLAB_WEBHOOK_SECRET_ID')
    logger.log_text(f"gitlab_webhook: {gitlab_webhook}", severity="DEBUG")
    
    project_id = os.environ.get('PROJECT_ID')
    logger.log_text(f"project_id: {project_id}", severity="DEBUG")
    
    gitlab_pat_secret_id = os.environ.get('GITLAB_PAT_SECRET_ID')
    logger.log_text(f"gitlab_pat_secret_id: {gitlab_pat_secret_id}", severity="DEBUG")
    
    

    # 1. Verify Request Authenticity:
    gitlab_token = request.headers.get('X-Gitlab-Token')
    if gitlab_token != gitlab_webhook:
        return "Invalid token", 403

    # Intiate Gitlab client
    gl = Gitlab("https://gitlab.com",
                private_token=gitlab_pat_secret_id)

    # Initialize Gemini API client
    vertexai.init(project=project_id, location="us-central1")

    event_type = request.headers.get('X-Gitlab-Event')
    payload = request.get_json()

    if event_type == "Merge Request Hook":
        handle_merge_request(payload, gl, logger)
    else:
        return "Unsupported event type", 200

    return "Webhook processed successfully", 200


def handle_merge_request(payload, gl, logger):
    """
    Handles merge request events from GitLab webhooks. This function determines
    whether the merge request is new, updated, or merged, and calls the appropriate
    handler functions for code review or wiki updates.

    Args:
        payload (dict): The JSON payload from the GitLab webhook event.
        gl (gitlab.Gitlab): An instance of the GitLab API client.
        logger (google.cloud.logging.Logger, optional): The logger to use for logging messages.

    Returns:
        None. (Actions are performed by calling other functions.)

    Raises:
        N/A (Errors are logged using the logger)
    """
    action = payload["object_attributes"]["action"]
    if DEBUG_MODE: logger.log_text(f"Action found: {action}", severity="DEBUG")

    if action == "merge":
        if DEBUG_MODE:logger.log_text("Action is merge, going to update wiki.", severity="DEBUG")
        #handle_wiki_update_on_merge(payload, gl, logger)

    elif action == "update" and "oldrev" in payload["object_attributes"]:
        if DEBUG_MODE:logger.log_text("Action is update and oldrev exists. Performing code review", severity="DEBUG")
        diff_obj = get_latest_commit_diff(payload, gl, logger)
        response = get_code_review_response_from_gemini(diff_obj, logger)
        if not response:
            logger.log_text(f"No feedback provided by Gemini for merge request {payload["object_attributes"]["iid"]}", severity="WARNING")
            return
        for line_comment in response:
            post_diff_discussion(payload, gl, line_comment, logger)
        response_summary = get_code_review_summary_from_gemini(response, logger)
        post_merge_request_summary(payload, response_summary, gl, logger)
    elif action == "open" or action == "reopen":
        if DEBUG_MODE:logger.log_text("Action is open. Performing code review", severity="DEBUG")
        diffs = get_merge_diffs(payload, gl, logger)
        response = []
        for diff_obj in diffs:
            response += get_code_review_response_from_gemini(diff_obj, logger)['responses']
            if not response:
                logger.log_text(f"No feedback provided by Gemini for merge request {payload["object_attributes"]["iid"]}", severity="WARNING")
                return
            for line_comment in response:
                post_diff_discussion(payload, gl, line_comment, logger)
        response_summary = get_code_review_summary_from_gemini(response, logger)
        post_merge_request_summary(payload, response_summary, gl, logger)   
    else:
        logger.log_text(f"Merge request action '{action}' not handled or no new changes detected.", severity="INFO")

def build_position(review_item, mr):
    """Builds a position object for a thread based on the review item.

    Args:
        review_item (dict): A dictionary containing review details
                           (new_line, old_line, new_file_path, old_file_path).
        mr (gitlab.v4.objects.merge_requests.ProjectMergeRequest): A GitLab merge request object.

    Returns:
        dict: A position object for the thread, or None if invalid.
    """
    
    new_line = review_item.get('new_line')
    old_line = review_item.get('old_line')

    if new_line >= 0 and old_line >= 0:
        return {
            'position_type': 'text',
            'new_path': review_item['new_file_path'],
            'new_line': new_line + 1,
            'old_path': review_item.get('old_file_path', review_item['new_file_path']),  
            'old_line': old_line + 1,
            'base_sha': mr.diff_refs['base_sha'],
            'head_sha': mr.diff_refs['head_sha'],
            'start_sha': mr.diff_refs['start_sha']
        }
    elif new_line >= 0:
        return {
            'position_type': 'text',
            'new_path': review_item['new_file_path'],
            'old_path': review_item.get('old_file_path', review_item['new_file_path']), 
            'new_line': new_line + 1,
            'base_sha': mr.diff_refs['base_sha'],
            'head_sha': mr.diff_refs['head_sha'],
            'start_sha': mr.diff_refs['start_sha']
        }
    elif old_line >= 0:
        return {
            'position_type': 'text',
            'new_path': review_item['new_file_path'],
            'old_path': review_item.get('old_file_path', review_item['new_file_path']), 
            'old_line': old_line + 1,
            'base_sha': mr.diff_refs['base_sha'],
            'head_sha': mr.diff_refs['head_sha'],
            'start_sha': mr.diff_refs['start_sha']
        }
    else:
        return None  


def post_diff_discussion(payload, gl, line_comment, logger):
    """
    Posts a code review comment as a discussion on a specific line in a GitLab merge request.

    Args:
        payload (dict): The JSON payload from the GitLab webhook event.
        gl (gitlab.Gitlab): An authenticated GitLab API client instance.
        line_comment (dict): A dictionary containing the line number and comment text generated by Gemini.
        logger (google.cloud.logging.Logger, optional): The logger to use for logging messages. If not provided,
                                                      logs will be printed to stdout.

    Returns:
        None

    Raises:
        N/A (Errors are logged using the logger)
    """
    try:
        project_id = payload["project"]["id"]
        merge_request_iid = payload["object_attributes"]["iid"]
        project = gl.projects.get(project_id)
        mr = project.mergerequests.get(merge_request_iid)
        position = build_position(line_comment, mr)
        mr.discussions.create({
            'body': line_comment['comment'],
            'position': position
            })
        message = f"Code review comment added for line {line_comment['new_line']} in {line_comment['new_file_path']}"
        if DEBUG_MODE:logger.log_text(message, severity="DEBUG")

    except Exception as e:
        logger.log_text(f"Error posting code review discussion: {e}",severity="ERROR")
        return "Error posting code review discussion. Please try again later."


def get_code_review_response_from_gemini(diffs, logger):
    """
    Fetches a code review from the Gemini Pro model on Vertex AI, based on the provided GitLab diff object.

    This function constructs a prompt instructing Gemini Pro to analyze the changes in the diff
    and provide a detailed code review in JSON format. It then calls the Gemini Pro API to generate
    the review, parses the JSON response, and returns the extracted code review comments.

    Args:
        diff_obj (gitlab.v4.objects.merge_requests.ProjectMergeRequestDiff): A GitLab Diff object containing
            the changes to be reviewed.
        logger (google.cloud.logging.Logger, optional): A logger for recording messages. If not provided,
            messages will be printed to stdout.

    Returns:
        list: A list of dictionaries, where each dictionary represents a comment on a specific line
            or file in the code changes. The dictionaries have the following keys:

            * new_line: The line number of the change in the new file (int).
            * old_line: The line number of the change in the old file (int).
            * new_file_path: The path to the modified or new file (str).
            * old_file_path: The original path to the file if it was renamed or moved (str).
            * comment: The code review comment in Markdown format (str).
            * severity: The severity of the comment ('minor', 'moderate', 'major', 'critical').

        Returns an empty list if there are no code review comments or if an error occurs.

    Raises:
        N/A (Errors are logged using the logger)

    """
    output_response_schema = {
        "type": "object",
        "properties": {
            "responses": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                    "new_line": {
                        "type": "integer"
                    },
                    "old_line": {
                        "type": "integer"
                    },
                    "new_file_path": {
                        "type": "string"
                    },
                    "old_file_path": {
                        "type": "string"
                    },
                    "comment": {
                        "type": "string"
                    },
                    "severity": {
                        "type": "string"
                    }
                    },
                    "required": [
                    "new_line",
                    "old_line",
                    "new_file_path",
                    "old_file_path",
                    "comment",
                    "severity"
                    ]
                }
            }
        }
    }
    
    system_instructions = [
            "You are a helpful code reviewer. Your mission is to review the code changes for a ROS2 package and provide feedback based on the changes.",
            
            """The Changes will be provided as a JSON Array of Changes.
            
            Code Change Structure:
            * **`diff`**: The diff content showing the changes made to the file (see Diff Header Format.)
            * **`new_path`**: The path to the modified or new file.
            * **`old_path`**: The original path to the file (if it was renamed or moved).
            * **`a_mode`**: The mode of the file before the change.
            * **`b_mode`**: The mode of the file after the change.
            * **`new_file`**: Whether the file is a new file or not.
            * **`renamed_file`**: Whether the file was renamed or moved.
            * **`deleted_file`**: Whether the file was deleted or not.
            * **'generated_file`**: Whether the file was generated by AI or not.""",
            
            """The diff header will be in the following format:
            ```Diff Header Format
            @@ -[start line],[number of lines] +[start line],[number of lines] @@
            ```
            * **`@@`**: This is the opening encapsulation to identify the diff header.
            * **`-`**: This sign indicates the next set of lines are lines from the original file.
            * **`+`**: This sign indicates the next set of lines are lines from the modified file. 
            * **`[start line],[number of lines]`**: This indicates the starting line of the change and the number of lines affected.
            * **`@@`**: This is the closing encapsulation to identify the diff header.
            
            ```Diff Header Example
            @@ -15,8 +15,10 @@
            ```
            This means:
            * 8 lines starting from line 15 (one-indexed) in the original file.
            * 10 lines starting from line 15 (one-indexed) in the modified file.
            
            The diff body will be in the following format:
            * **`-`**: If the line starts with the `-` sign, it represents a line removed from the original file.
            * **`+`**: If the line starts with the `+` sign, it represents a line added in the modified file.
            * ** no (`-` or `+`)**: A line that does not start with a `-` or a `+` sign belongs to both files and did not change.""", 

            """When reviewing the code, please focus on the following aspects:

            * **Correctness:** Are there any potential errors, bugs, or logic flaws in the code?
            * **Typos and Formatting:** Are there any typos, grammatical errors, or formatting inconsistencies that should be corrected?
            * **Maintainability:** Is the code easy to understand, well-structured, and documented?  Are there opportunities to simplify or refactor the code?
            * **Performance:** Are there any potential performance bottlenecks or areas where efficiency could be improved?
            * **Security:** Are there any security vulnerabilities or potential risks (e.g., input validation, error handling)?
            * **ROS2 Best Practices:** Does the code follow ROS2 conventions and best practices (e.g., node naming, parameter usage, message types)?""",

            """You **MUST** label comments according to importance:

            * **minor**: For minor issues like typos or formatting inconsistencies.
            * **moderate**: For issues that affect code quality but aren't critical.
            * **major**: For significant issues that could lead to errors or problems.
            * **critical**: For critical errors or vulnerabilities that require immediate attention.""",
            
            """Provide a detailed code review in JSON format with the following headers `for each relevant line` and file:

            * **`new_line`**: the exact line in the new file that was added (MUST start with a `+` sign) that the comment applies to. 
            * **`old_line`**: the exact line in the old file that was modified (MUST start with a `-` sign) that the comment applies to.
            * **`new_file_path`**: The path to the file where the change occurred (e.g., "README.md").
            * **`old_file_path`**: The original path to the file (if it was renamed or moved).
            * **`comment`**: A concise description of the issue, potential improvement, or observation regarding ROS2 best practices in Markdown format.
            * **`severity`**: The severity of the issue ('minor', 'moderate', 'major', 'critical').""",
            
            """**Special Instructions:**

            * To comment on a line that was added, the `new_line` attribute should be filled, and the `old_line` attribute should be -1.
            * To comment on a line that was removed, the `new_line` attribute should be -1, and the `old_line` attribute should be filled.
            * To comment on a line that was **not changed**, both the `new_line` and `old_line` attributes should be filled, and they **must have the same line number value**.
            * Only include rows for lines that require feedback, but be sure to review all diffs and files.""",

            """**Additional Emphasis**

            * Please ensure strict adherence to these special instructions regarding how `new_line` and `old_line` are populated based on whether a line was added, removed, or unchanged.
            * new_line and old_line MUST be exactly the line the comment refers to or -1. Please ensure they are exactly correct."""
        ]
    
    

    model = GenerativeModel(
        model_name= MODEL_ID,
        generation_config=GenerationConfig(response_mime_type="application/json", 
                                           response_schema=output_response_schema,
                                           candidate_count=1),
        system_instruction=system_instructions)

    prompt = f'''Review the following code changes in diff format, provided as a JSON array:

            
            ```json
            {json.dumps(diffs, indent=2)}
            ```
            '''

    
    response = model.generate_content(prompt)
    if DEBUG_MODE:logger.log_text(f"Code review response: {response}", severity="DEBUG")
    comments = json.loads(response.candidates[0].content.parts[0].text)
    if DEBUG_MODE:logger.log_text(f"Code review response: {comments}", severity="DEBUG")
    return comments


def post_merge_request_summary(payload, feedback, gl, logger):
    """
    Posts the summary of a code review as a note (comment) on a GitLab merge request.

    Args:
        payload (dict): The JSON payload from the GitLab webhook event.
        feedback (str): The summary feedback string generated by Gemini.
        gl (gitlab.Gitlab): An authenticated GitLab API client instance.
        logger (google.cloud.logging.Logger, optional): A logger for recording messages. 
                                                      If not provided, logs will be printed to stdout.

    Returns:
        None

    Raises:
        N/A (Errors are logged using the logger)
    """

    try:
        project_id = payload["project"]["id"]
        merge_request_iid = payload["object_attributes"]["iid"]

        project = gl.projects.get(project_id)
        mr = project.mergerequests.get(merge_request_iid)
        if DEBUG_MODE:logger.log_text(f"Posting summary feedback: {feedback}", severity="DEBUG")
        mr.notes.create({
            'body': feedback
        })

    except Exception as e:
        logger.log_text(f"Error posting code review comment: {e}", severity="ERROR")
        return "Error posting code review comment. Please try again later."


def get_latest_commit_diff(payload, gl, logger):
    """Fetches the diff for the latest commit in a GitLab merge request.

    Args:
        payload (dict): The JSON payload from the GitLab webhook event, 
                       containing the merge request information.
        gl (gitlab.Gitlab): An authenticated Gitlab API client instance.
        logger (google.cloud.logging.Logger, optional): A logger for recording messages.
                                                      If not provided, logs will be printed to stdout. 

    Returns:
        list: A list of dictionaries representing the diffs for each changed file in the latest commit,
              or an empty list if there are no diffs or an error occurs. Each dictionary contains:
              - diff (str): The raw diff content for the file.
              - new_path (str): The path of the file in the source branch.
              - old_path (str): The path of the file in the target branch.
              - a_mode, b_mode (str): File modes (not used in this context).
              - new_file, renamed_file, deleted_file (bool): Flags indicating file status.

    Raises:
        N/A (Errors are logged using the logger)"""

    try:
        project_id = payload["project"]["id"]
        commit_id = payload["object_attributes"]["last_commit"]["id"]
        project = gl.projects.get(project_id)
        commit = project.commits.get(commit_id)
        diff = commit.diff()
        if DEBUG_MODE:logger.log_text(f"diff: {json.dumps(diff, indent=2)} , Commit: {json.dumps(payload["object_attributes"]["last_commit"], indent=2)}",severity="DEBUG")
        
        return diff
    except Exception as e:
        logger.log_text(f"Error fetching diffs: {e}", severity="ERROR")
        return "Error fetching code change diffs. Please try again later."


def get_code_review_summary_from_gemini(responses, logger):
    """
    Generates a summary of code review comments from the Gemini Pro model on Vertex AI.

    This function takes a list of code review comments (previously generated by Gemini Pro),
    constructs a prompt asking Gemini Pro to summarize them, and then calls the Gemini Pro
    API to generate a concise summary. The summary is returned as a string in Markdown format.

    Args:
        responses (list): A list of dictionaries, where each dictionary represents a
            single code review comment. Each dictionary should contain the following keys:
            - new_line: The line number of the change in the new file (int).
            - old_line: The line number of the change in the old file (int).
            - new_file_path: The path to the modified or new file (str).
            - old_file_path: The original path to the file if it was renamed or moved (str).
            - comment: The code review comment in Markdown format (str).
            - severity: The severity of the comment ('minor', 'moderate', 'major', 'critical').
        logger (google.cloud.logging.Logger): A logger for recording messages. 

    Returns:
        str: A markdown-formatted string summarizing the key points and recommendations from the code review comments.
        If there are no comments or an error occurs, an empty string is returned.

    Raises:
        N/A (Errors are logged using the logger)
    """

    summary_prompt = f"""Summarize the following code review comments, which are provided in JSON format: 
    
    Review Comments Structure:
    
    * **`new_line`**: the line in the new file that was added (started with a `+` sign) that the comment applies to. 
    * **`old_line`**: the line in the old file that was modified (started with a `-` sign) that the comment applies to. 
    * **`new_file_path`**: The path to the file where the change occurred (e.g., "README.md").
    * **`old_file_path`**: The original path to the file (if it was renamed or moved).
    * **`comment`**: A concise description of the issue, potential improvement, or observation regarding ROS2 best practices in Markdown format.
    * **`severity`**: The severity of the issue ('minor', 'moderate', 'major', 'critical').
    
    Comments in JSON format:
    
    {json.dumps(responses, indent=2)}

    Focus on the following in your summary:

    * **Key Issues:** (Major and Critical) Highlight the main problems identified in the code review.
    * **Suggested Improvements:** (Minor and Moderate) Briefly outline the recommendations given for fixing or enhancing the code.
    * **ROS2 Specific Concerns:** If any comments address ROS2-specific conventions or best practices, mention them separately.

    **Desired Output Format:**

    A concise list of bullet points summarizing the key findings and recommendations from the code review in Markdown format.
    """
    model = GenerativeModel(
        model_name= MODEL_ID,
        system_instruction=[
            "You are a helpful code reviewer.",
            "Your mission is to summarize the code review comments provided.",
        ],)
    contents = [summary_prompt]
    try:
        response = model.generate_content(contents)
        summary_text = response.candidates[0].content.parts[0].text
        if DEBUG_MODE:logger.log_text(f"Summary: {summary_text}", severity="DEBUG")
        return summary_text
    except Exception as e:
        logger.log_text(f"Error generating summary: {e}", severity="ERROR")
        return ""  

def get_merge_diffs(payload, gl, logger):
    """
    Fetches all diff objects associated with a merge request in GitLab.

    This function extracts the project ID and merge request ID from the webhook payload,
    retrieves the corresponding merge request object using the GitLab API client, and then
    fetches all diff objects associated with the merge request in batches. It also logs
    relevant information for debugging purposes.

    Args:
        payload (dict): The JSON payload received from the GitLab webhook event,
                        containing information about the merge request.
        gl (gitlab.Gitlab): An authenticated GitLab API client instance.
        logger (google.cloud.logging.Logger): A logger for recording messages.

    Returns:
        list: A list of gitlab.v4.objects.merge_requests.ProjectMergeRequestDiff objects, each
            representing a diff for a file changed in the merge request.
            Returns an empty list if no diffs are found or an error occurs.
    """

    try:
        project_id = payload["project"]["id"]
        merge_request_iid = payload["object_attributes"]["iid"]
        logger.log_text(f"Fetching diffs for merge request {merge_request_iid} in project {project_id}", severity="DEBUG")

        project = gl.projects.get(project_id)
        mr = project.mergerequests.get(merge_request_iid)

        diffs = []

        # Retrieve diff information
        partial_diffs = mr.diffs.list()
        for partial_diff in partial_diffs:
            diff = mr.diffs.get(partial_diff.id)
            logger.log_text(f"Fetched diff for merge request {merge_request_iid} in project {project_id}: {diff.diffs}", severity="DEBUG")
            diffs += diff.diffs
            
        if DEBUG_MODE:logger.log_text(f"Retrieved {len(diffs)} diffs for merge request {merge_request_iid}", severity="DEBUG")

        return diffs
    except Exception as e:
        error_msg = f"Error fetching diffs: {e}"
        logger.log_text(error_msg, severity="ERROR")
        return []


def handle_wiki_update_on_merge(payload, gl, logger):
    """
    Handles wiki updates based on a merged merge request in GitLab.

    This function extracts relevant information from the merge request payload,
    identifies wiki pages to update based on labels, generates new content using
    the Gemini Pro model, and then updates or creates the corresponding wiki pages in GitLab.

    Args:
        payload (dict): The JSON payload from the GitLab webhook event containing merge request details.
        gl (gitlab.Gitlab): An authenticated Gitlab API client instance.
        logger (google.cloud.logging.Logger): A logger for recording messages.

    Returns:
        str: An informative message indicating the success or failure of the operation.

    Raises:
        N/A (Errors are logged using the logger)
    """

    try:

        project_id = payload["project"]["id"]
        merge_request_iid = payload["object_attributes"]["iid"]
        if DEBUG_MODE:logger.log_text(
            f"Handling wiki update for merge request {merge_request_iid} in project {project_id}",
            severity="DEBUG",
        )

        project = gl.projects.get(project_id)
        mr = project.mergerequests.get(merge_request_iid)

        title = mr.title
        description = mr.description

        labels = mr.labels
        relevant_tags = [label for label in labels if label.startswith("docs::")]
        
        diffs = get_merge_diffs(payload, gl, logger)
        changes = []
        for diff_obj in diffs:
            changes += diff_obj.diffs

        for tag in relevant_tags:
        
            target_wiki_page_slug = tag.replace("docs::", "", 1)
            if target_wiki_page_slug:

                try:
                    page = project.wikis.get(target_wiki_page_slug)
                except Gitlab.exceptions.GitlabGetError:
                    page = project.wikis.create({'title': target_wiki_page_slug})
                if DEBUG_MODE:logger.log_text(
                    f"Updating or creating wiki page: {target_wiki_page_slug}",
                    severity="DEBUG",
                )

                existing_content = page.content

                prompt = f"""Summarize the changes in this merged merge request, focusing on the information relevant to the '{target_wiki_page_slug}' wiki page.
                Update the existing content if it exists, or create a new wiki page with the following information:

                Existing Content:
                {existing_content}

                **Merge Request Title:** {title}
                **Merge Request Description:** {description}
                **Commit Messages (JSON format):** {json.dunmps([commit["message"] for commit in mr.commits()], indent=2)}
                **Changes (JSON format):** {json.dumps(changes, indent=2)}
                Generate content suitable for the wiki page, including headings, lists, and code snippets where appropriate. Use Markdown formatting.
                """

                model = GenerativeModel(
                    model_name=MODEL_ID,
                    system_instruction=[
                        "You are a helpful wiki page writer and expert markdown writer.",
                        "Your mission is write a wiki page based on the changes provided",
                    ],)
                contents = [prompt]
                page.content = model.generate_content(contents).candidates[0].content.parts[0].text
                page.save()

                if DEBUG_MODE:logger.log_text(f"Wiki page '{target_wiki_page_slug}' updated successfully.", severity="DEBUG")

    except Exception as e:
        logger.log_text(f"Error updating wiki: {e}", severity="ERROR")
        return "Error updating wiki. Please try again later."

