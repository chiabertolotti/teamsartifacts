# Microsoft Teams JSON Artifacts Parser for Autopsy

This professionally-architected Autopsy ingest module processes Microsoft Teams artifacts exported as JSON, providing forensic examiners with comprehensive, structured visualization of communications, user activities, and metadata with enterprise-grade reliability.

## Overview
This advanced ingest module systematically parses exported Teams JSON files (obtained via DFIndexedDB) using a modular, maintainable architecture. The module facilitates detailed analysis of messages, calls, meetings, reactions, mentions, and user interactions directly within the Autopsy platform, streamlining investigation workflows with improved code quality and documentation.

---

## Features

| Category | Description |
| :--- | :--- |
| **Artifact Extraction** | Parses JSON to extract messages, calls, meetings, threads, members, mentions, and reactions. |
| **Data Enrichment** | Automatically enriches user IDs (MRIs) with contact names, displaying them in the user-friendly format: `"ID (Name)"` across all relevant artifacts. |
| **Robust Parsing** | Handles various Teams message types (Text, HTML, forwarded, replied) and robustly processes timestamps (normalized to UTC) and complex content structures. |
| **Multi-Step Processing** | Processes files in a specific order to establish *Tenant Mapping* and contact enrichment *before* parsing message content. |
| **HTML Content Processing** | Advanced HTML cleaning for RichText/Html messages, including extraction of emoji characters, handling of Reply/Forward blockquotes with pre-text inclusion. |
| **Inline Images (AMSImage)** | Recognizes and extracts inline images (AMSImage) as attachments while preserving original HTML content in message artifacts. |
| **GIF/Sticker/Emoji Support** | Handles GIF, Sticker, and Emoji content with proper attachment creation and emoji character display in message content. |
| **Compatibility** | Compatible with the Jython environment in Autopsy (supporting Python 2 and 3). |

---

## Prerequisites and Installation

### Requirements

To use this module, you must first export the Teams IndexedDB database content into structured JSON files (e.g., `output_people.json`, `output_conversations.json`, `output_replychains.json`) using **DFIndexedDB** as described in [data-extraction/README](./data-extraction/README.md).

### Installation

1.  Copy the `teamsartifacts.py` file and any necessary supporting files to your Autopsy Python modules directory (e.g., `C:\Users\<your_user>\AppData\Roaming\autopsy\python_modules\teamsartifacts\`).
2.  Start Autopsy.
3.  The module will appear as **"Teams JSON Visualization"** in the Ingest Modules list when setting up or running an ingest.

---

## Artifact Processing Order

The module ensures data consistency and enrichment by processing the input files in the following sequence:

1.  `output_people.json`: Processed first to load all contact information, creating a comprehensive mapping of MRIs to display names for enrichment.
2.  `output_conversations.json`: Processed second to establish tenant mappings and conversation metadata, ensuring all subsequent artifacts can be accurately associated with the correct tenant ID.
3.  `output_replychains.json` and other files: Processed last to extract messages, calls, and activities, ensuring all data is enriched with contact names and tenant IDs.

---

## Key Artifact Categories

The module defines the following custom artifact categories, registered in the Autopsy *Blackboard* under the custom namespace `TSK_TEAMS_`.


| Artifact Name                        | TSK Type                   | Description                                                                                        |
| :----------------------------------- | :------------------------- | :------------------------------------------------------------------------------------------------- |
| Microsoft Teams Call Activities      | `TSK_TEAMS_CALLLOG_MSG`    | Call-related activities (recordings, transcripts).                                                 |
| Microsoft Teams Calls                | `TSK_TEAMS_CALLLOG_CONV`   | Teams call log conversations (from call logs, not meetings).                                       |
| Microsoft Teams Channel              | `TSK_TEAMS_TEAMS_CHAT`     | Conversations within a Team (channel chats).                                                       |
| Microsoft Teams Contacts             | `TSK_TEAMS_CONTACTS`       | People/contacts information from the organization directory.                                       |
| Microsoft Teams Conversations Member | `TSK_TEAMS_THREAD_MEMBER`  | Members of a Teams thread with detailed information.                                               |
| Microsoft Teams Conversations        | `TSK_TEAMS_THREADINFO`     | General conversation threads not matching specific patterns.                                       |
| Microsoft Teams Group Chat           | `TSK_TEAMS_GROUP_CHAT`     | Group conversations.                                                                               |
| Microsoft Teams Meetings             | `TSK_TEAMS_EVENTCALL`      | Teams meeting events (e.g., scheduled meetings).                                                   |
| Microsoft Teams Mentions             | `TSK_TEAMS_MENTION`        | `@mentions` within messages.                                                                       |
| Microsoft Teams Messages             | `TSK_TEAMS_MESSAGE`        | A single Teams message (text/HTML, including replies/forwards).                                    |
| Microsoft Teams Attachments          | `TSK_TEAMS_MSG_ATTACHMENT` | Files, links, inline images (AMSImage), GIFs, stickers, and blurHash images attached to a message. |
| Microsoft Teams Private Chat         | `TSK_TEAMS_PRIVATE_CHAT`   | Private individual conversations.                                                                  |
| Microsoft Teams Reactions            | `TSK_TEAMS_REACTION`       | User reactions to messages (likes, emoticons).                                                     |

---

## Detailed Artifacts and Attributes

The following sections detail the custom artifacts and their attributes created by the Teams JSON Artifacts Parser within Autopsy.

### 1. Microsoft Teams Messages (`TSK_TEAMS_MESSAGE`)
Represents a single Teams message (text or HTML, including replies and forwards).

| Attribute Name | TSK Type | Description |
| :--- | :--- | :--- |
| Client Arrival | `TSK_TEAMS_CLIENT_ARRIVAL` | Client arrival timestamp (UTC). |
| Compose Time | `TSK_TEAMS_COMPOSE_TIME` | Compose time (UTC, if edited). |
| Message Content | `TSK_TEAMS_CONTENT` | Cleaned message content (plain text, reply/forward info, or extracted from HTML). |
| Conversation ID | `TSK_TEAMS_CONV_ID` | Conversation (thread) ID. |
| Message Author ID | `TSK_TEAMS_CREATOR` | Message author's unique identifier (MRI). |
| Author Display Name | `TSK_TEAMS_DISPLAY_NAME` | Display name of the message author. |
| Deletion Time | `TSK_TEAMS_DELETE_TIME` | Deletion time (UTC, if present). |
| Draft Saved Time | `TSK_TEAMS_DRAFT_TIME` | Draft saved time (UTC, if present). |
| Last Modified Time | `TSK_TEAMS_EDIT_TIME` | Last modified time (UTC, if present). |
| Contains Attachments | `TSK_TEAMS_HAS_ATTACHMENT` | Indicates presence of attachments (files/links). |
| Message ID | `TSK_TEAMS_MSG_ID` | Unique message ID. |
| Message Category | `TSK_TEAMS_MSG_TYPE` | Message category (e.g., Text, RichText/Html). |
| Server Received Time | `TSK_TEAMS_ORIG_ARRIVAL` | Server received timestamp (UTC). |
| Message Metadata | `TSK_TEAMS_PROPERTIES` | Original message metadata as JSON. |
| Sequence ID | `TSK_TEAMS_SEQ_ID` | Sequence ID within the conversation. |
| Tenant ID | `TSK_TEAMS_TENANTID` | Tenant ID for cross-organizational analysis. |

### 2. Microsoft Teams Attachments (`TSK_TEAMS_MSG_ATTACHMENT`)
Represents a file, link, inline image (AMSImage), GIF, sticker, or blurHash image attached to a Teams message.

| Attribute Name | TSK Type | Description |
| :--- | :--- | :--- |
| Attachment Name | `TSK_TEAMS_ATT_NAME` | File name, image description, or content type (e.g., "Sticker", "GIF", "AMSImage"). |
| Attachment Type | `TSK_TEAMS_ATT_TYPE` | File type, link type, 'AMSImage', 'gif', 'sticker', or 'blurHash' for various content types. |
| Attachment URL | `TSK_TEAMS_ATT_URL` | URL of the link, image, GIF, or sticker source (if applicable). |
| Conversation ID | `TSK_TEAMS_CONV_ID` | Conversation (thread) ID. |
| Message ID | `TSK_TEAMS_MSG_ID` | Parent message ID. |
| Tenant ID | `TSK_TEAMS_TENANTID` | Tenant ID. |

### 3. Microsoft Teams Calls (`TSK_TEAMS_CALLLOG_CONV`)
Represents a Teams call log conversation (from call logs, not meetings).

| Attribute Name | TSK Type | Description |
| :--- | :--- | :--- |
| Call Duration | `TSK_TEAMS_CALLLOG_DURATION_CALC` | Calculated call duration in HH:MM:SS format. |
| Call Session ID | `TSK_TEAMS_CALLLOG_CALLID2` | Call session ID (from call-log). |
| Call Type | `TSK_TEAMS_CALLLOG_CALLTYPE` | Type of call (e.g., audio, video). |
| Compose Time | `TSK_TEAMS_COMPOSE_TIME` | Compose time (UTC, if present). |
| Content | `TSK_TEAMS_CONTENT` | Message content (call log details). |
| Conversation ID | `TSK_TEAMS_CONV_ID` | Conversation (thread) ID (should be '48:calllogs'). |
| Delete Time | `TSK_TEAMS_DELETE_TIME` | Delete time (UTC, if present). |
| Direction | `TSK_TEAMS_CALLLOG_DIRECTION` | Call direction (incoming/outgoing). |
| Edit Time | `TSK_TEAMS_EDIT_TIME` | Edit time (UTC, if present). |
| Message ID | `TSK_TEAMS_MSG_ID` | Message ID. |
| Message Type | `TSK_TEAMS_MSG_TYPE` | Message type (should be 'Text'). |
| Original Arrival | `TSK_TEAMS_ORIG_ARRIVAL` | Original arrival timestamp (UTC). |
| Originator | `TSK_TEAMS_CALLLOG_ORIGINATOR` | Originator participant ID and name in format "ID (Name)". |
| Participants | `TSK_TEAMS_CALLLOG_PARTICIPANTS` | List of participants (as JSON). |
| Properties | `TSK_TEAMS_PROPERTIES` | Original properties as JSON. |
| Sequence ID | `TSK_TEAMS_SEQ_ID` | Sequence ID. |
| Start Time | `TSK_TEAMS_CALLLOG_STARTTIME` | Call start time (readable string). |
| State | `TSK_TEAMS_CALLLOG_STATE` | Call state (e.g., completed, missed). |
| Target Participant | `TSK_TEAMS_CALLLOG_TARGET` | Target participant ID and name in format "ID (Name)". |
| Tenant ID | `TSK_TEAMS_TENANTID` | Tenant ID. |
| End Time | `TSK_TEAMS_CALLLOG_ENDTIME` | Call end time (readable string). |

### 4. Microsoft Teams Call Activities (`TSK_TEAMS_CALLLOG_MSG`)
Represents call-related activities (recordings, transcripts, etc.).

| Attribute Name | TSK Type | Description |
| :--- | :--- | :--- |
| Call Session ID | `TSK_TEAMS_CALLLOG_CALLID` | Call session ID. |
| Compose Time | `TSK_TEAMS_COMPOSE_TIME` | Compose time (UTC, if present). |
| Content | `TSK_TEAMS_CONTENT` | Content (call activity details). |
| Conversation ID | `TSK_TEAMS_CONV_ID` | Conversation (thread) ID. |
| Delete Time | `TSK_TEAMS_DELETE_TIME` | Delete time (UTC, if present). |
| Duration | `TSK_TEAMS_CALLLOG_DURATION` | Call/recording duration. |
| Edit Time | `TSK_TEAMS_EDIT_TIME` | Edit time (UTC, if present). |
| Initiator | `TSK_TEAMS_CALLLOG_INITIATOR` | Recording initiator ID with contact name enrichment in format "ID (Name)". |
| Meeting Organizer ID | `TSK_TEAMS_CALLLOG_MEETING_ORGID` | Meeting organizer ID with contact name enrichment in format "ID (Name)". |
| Message ID | `TSK_TEAMS_MSG_ID` | Message ID. |
| Message Type | `TSK_TEAMS_MSG_TYPE` | Message type (e.g., RichText/Media_CallRecording). |
| Original Arrival | `TSK_TEAMS_ORIG_ARRIVAL` | Original arrival timestamp (UTC). |
| Original Name | `TSK_TEAMS_CALLLOG_ORIGINALNAME` | Original recording file name. |
| Properties | `TSK_TEAMS_PROPERTIES` | Original properties as JSON. |
| Sequence ID | `TSK_TEAMS_SEQ_ID` | Sequence ID. |
| Status | `TSK_TEAMS_CALLLOG_STATUS` | Recording status. |
| Tenant ID | `TSK_TEAMS_TENANTID` | Tenant ID. |
| Terminator | `TSK_TEAMS_CALLLOG_TERMINATOR` | Recording terminator ID with contact name enrichment in format "ID (Name)". |
| Timestamp | `TSK_TEAMS_CALLLOG_TIMESTAMP` | Call/recording timestamp (formatted for readability). |

### 5. Microsoft Teams Meetings (`TSK_TEAMS_EVENTCALL`)
Represents Teams meeting events (not video calls).

| Attribute Name | TSK Type | Description |
| :--- | :--- | :--- |
| Call Event Type | `TSK_TEAMS_EVENTCALL_CALLEVENTTYPE` | Call event type (from content). |
| Call ID | `TSK_TEAMS_EVENTCALL_CALLID` | Call ID (from content). |
| Compose Time | `TSK_TEAMS_COMPOSE_TIME` | Compose time (UTC, if present). |
| Content | `TSK_TEAMS_CONTENT` | Content (meeting event details). |
| Conversation ID | `TSK_TEAMS_CONV_ID` | Conversation (thread) ID. |
| Conversation Start Time | `TSK_TEAMS_EVENTCALL_CONVSTARTTIME` | Conversation start time (from content). |
| Creator | `TSK_TEAMS_CREATOR` | Creator's unique identifier with contact name enrichment in format "ID (Name)". |
| Delete Time | `TSK_TEAMS_DELETE_TIME` | Delete time (UTC, if present). |
| Edit Time | `TSK_TEAMS_EDIT_TIME` | Edit time (UTC, if present). |
| Meeting Title | `TSK_TEAMS_EVENTCALL_MEETINGTITLE` | Meeting title (from properties['meeting']). |
| Meeting Type | `TSK_TEAMS_EVENTCALL_MEETINGTYPE` | Meeting type (e.g., scheduled, ad-hoc). |
| Message ID | `TSK_TEAMS_MSG_ID` | Message ID. |
| Message Type | `TSK_TEAMS_MSG_TYPE` | Message type (should be 'Event/Call'). |
| Original Arrival | `TSK_TEAMS_ORIG_ARRIVAL` | Original arrival timestamp (UTC). |
| Organizer UPN | `TSK_TEAMS_EVENTCALL_ORGANIZERUPN` | Organizer's UPN (user principal name). |
| Participants | `TSK_TEAMS_EVENTCALL_PARTICIPANTS` | Formatted list of participants showing "ID (DisplayName) - Duration: XXX seconds" (one per line). |
| Properties | `TSK_TEAMS_PROPERTIES` | Original properties as JSON. |
| Sequence ID | `TSK_TEAMS_SEQ_ID` | Sequence ID. |
| Start Time | `TSK_TEAMS_EVENTCALL_STARTTIME` | Meeting start time (if present). |
| Tenant ID | `TSK_TEAMS_TENANTID` | Tenant ID. |
| End Time | `TSK_TEAMS_EVENTCALL_ENDTIME` | Meeting end time (if present). |

### 6. Microsoft Teams Conversations (`TSK_TEAMS_THREADINFO`)
Represents general Teams conversation threads that don't match specific patterns. *Note: Team ID is not displayed for general conversations.*

| Attribute Name | TSK Type | Description |
| :--- | :--- | :--- |
| Created At | `TSK_TEAMS_CREATEDAT` | Thread creation time. |
| Creator | `TSK_TEAMS_CREATOR` | Thread creator with contact name enrichment in format "ID (Name)". |
| Tenant ID | `TSK_TEAMS_TENANTID` | Tenant ID. |
| Thread ID | `TSK_TEAMS_THREAD_ID` | Thread ID. |
| Thread Type | `TSK_TEAMS_THREAD_TYPE` | Thread type (e.g., Space, Topic, Chat). |
| Topic | `TSK_TEAMS_TOPIC` | Thread topic/title. |

### 7. Microsoft Teams Group Chat (`TSK_TEAMS_GROUP_CHAT`)
Represents Teams group conversations (conversation ID ends with `@thread.v2`). *Note: Team ID is not displayed for Group Chat conversations.*

| Attribute Name | TSK Type | Description |
| :--- | :--- | :--- |
| Created At | `TSK_TEAMS_CREATEDAT` | Thread creation time. |
| Creator | `TSK_TEAMS_CREATOR` | Thread creator with contact name enrichment in format "ID (Name)". |
| Tenant ID | `TSK_TEAMS_TENANTID` | Tenant ID. |
| Thread ID | `TSK_TEAMS_THREAD_ID` | Thread ID. |
| Thread Type | `TSK_TEAMS_THREAD_TYPE` | Thread type (e.g., Space, Topic, Chat). |
| Topic | `TSK_TEAMS_TOPIC` | Thread topic/title. |

### 8. Microsoft Teams Private Chat (`TSK_TEAMS_PRIVATE_CHAT`)
Represents Teams private conversations (conversation ID ends with `@unq.gbl.spaces`). *Note: Team ID is not displayed for Private Chat conversations.*

| Attribute Name | TSK Type | Description |
| :--- | :--- | :--- |
| Created At | `TSK_TEAMS_CREATEDAT` | Thread creation time. |
| Creator | `TSK_TEAMS_CREATOR` | Thread creator with contact name enrichment in format "ID (Name)". |
| Tenant ID | `TSK_TEAMS_TENANTID` | Tenant ID. |
| Thread ID | `TSK_TEAMS_THREAD_ID` | Thread ID. |
| Thread Type | `TSK_TEAMS_THREAD_TYPE` | Thread type (e.g., Space, Topic, Chat). |
| Topic | `TSK_TEAMS_TOPIC` | Thread topic/title. |

### 9. Microsoft Teams Teams (`TSK_TEAMS_TEAMS_CHAT`)
Represents Teams conversations within a team (conversation ID ends with `@thread.tacv2`).

| Attribute Name | TSK Type | Description |
| :--- | :--- | :--- |
| Created At | `TSK_TEAMS_CREATEDAT` | Thread creation time. |
| Creator | `TSK_TEAMS_CREATOR` | Thread creator with contact name enrichment in format "ID (Name)". |
| Team ID | `TSK_TEAMS_TEAMID` | Team ID *(only displayed for Teams conversations)*. |
| Tenant ID | `TSK_TEAMS_TENANTID` | Tenant ID. |
| Thread ID | `TSK_TEAMS_THREAD_ID` | Thread ID. |
| Thread Type | `TSK_TEAMS_THREAD_TYPE` | Thread type (e.g., Space, Topic, Chat). |
| Topic | `TSK_TEAMS_TOPIC` | Thread topic/title. |

### 10. Microsoft Teams Conversations Member (`TSK_TEAMS_THREAD_MEMBER`)
Represents the members of a Teams thread with detailed information.

| Attribute Name | TSK Type | Description |
| :--- | :--- | :--- |
| Member Information | `TSK_TEAMS_MEMBER_ID` | Detailed member information including: Name, Email, MRI, and Type (e.g., ADUser). |
| Tenant ID | `TSK_TEAMS_TENANTID` | Tenant ID. |
| Thread ID | `TSK_TEAMS_THREAD_ID` | Thread ID. |

### 11. Microsoft Teams Contacts (`TSK_TEAMS_CONTACTS`)
Represents people/contacts information from the organization directory (from `output_people.json`).

| Attribute Name | TSK Type | Description |
| :--- | :--- | :--- |
| Display Name | `TSK_TEAMS_CONTACT_DISPLAYNAME` | Full display name. |
| Email Address | `TSK_TEAMS_CONTACT_EMAIL` | Email address. |
| Microsoft Resource Identifier | `TSK_TEAMS_CONTACT_MRI` | Unique Microsoft identifier. |
| Name | `TSK_TEAMS_CONTACT_GIVEN_NAME` | First name. |
| Surname | `TSK_TEAMS_CONTACT_SURNAME` | Last name. |
| Tenant Name | `TSK_TEAMS_CONTACT_TENANT` | Organization tenant name. |

### 12. Microsoft Teams Mentions (`TSK_TEAMS_MENTION`)
Represents `@mentions` within Teams messages.

| Attribute Name | TSK Type | Description |
| :--- | :--- | :--- |
| Conversation ID | `TSK_TEAMS_MENTION_CONV_ID` | Conversation (thread) ID. |
| Display Name | `TSK_TEAMS_MENTION_DISPLAYNAME` | Display name of the mentioned user. |
| Message ID | `TSK_TEAMS_MSG_ID` | Message ID containing the mention. |
| Mention MRI | `TSK_TEAMS_MENTION_MRI` | Mentioned user's MRI (unique identifier). |
| Mention Type | `TSK_TEAMS_MENTION_TYPE` | Type of mention (e.g., user, team). |
| Tenant ID | `TSK_TEAMS_TENANTID` | Tenant ID. |

### 13. Microsoft Teams Reactions (`TSK_TEAMS_REACTION`)
Represents reactions (emoticons, likes, etc.) to Teams messages.

| Attribute Name | TSK Type | Description |
| :--- | :--- | :--- |
| Message ID | `TSK_TEAMS_REACTION_MSG_ID` | Message ID. |
| Reaction Time | `TSK_TEAMS_REACTION_TIME` | Reaction timestamp (UTC). |
| Reaction Type | `TSK_TEAMS_REACTION_TYPE` | Type of reaction (e.g., like, heart, emoji). |
| Sequence ID | `TSK_TEAMS_REACTION_SEQ_ID` | Sequence ID. |
| Tenant ID | `TSK_TEAMS_TENANTID` | Tenant ID. |
| User MRI | `TSK_TEAMS_REACTION_MRI` | User MRI who reacted with contact name enrichment in format "ID (Name)". |

---

## Code Architecture Improvements

### Professional Code Structure
The current implementation adopts a modular architecture, incorporating the following enhancements:

| Component | Description |
| :--- | :--- |
| **Modular Processing** | Specialized methods for each artifact type (`_process_messages`, `_process_call_log`, `_process_meeting_event`, etc.). |
| **Error Handling** | Comprehensive error logging with `_log_error()` method for debugging and monitoring. |
| **Utility Methods** | Reusable functions for timestamp parsing, participant formatting, and duration calculations. |
| **Professional Documentation** | Complete English documentation with detailed docstrings for all methods. |
| **Attribute Consistency** | Standardized naming conventions for all forensic attributes. |

### Enhanced Data Processing
- **Call Duration Calculations**: Automatic calculation of call durations with multiple timestamp format support.
- **Contact Enrichment**: Advanced participant information formatting with fallback mechanisms.
- **Meeting Metadata Extraction**: Intelligent extraction of meeting attributes from various content formats.
- **Reaction Processing**: Comprehensive emoticon and reaction metadata handling.
- **Robust Parsing**: Multiple fallback mechanisms for timestamp and content parsing.

---

## Key Functions

| Function Name | Description |
| :--- | :--- |
| **Main Processing Methods** | |
| `startUp(self, context)` | Initializes the parser with modular attribute setup and prepares internal mappings for contacts and conversations. |
| `process(self, dataSource, progressBar)` | Main entry point with improved error handling. Finds Teams JSON files, loads contacts, then processes all artifacts. |
| **Specialized Processing Methods** | |
| `_process_messages(self, messages, thread_val, data_source, tenant_id)` | Processes Teams messages with enhanced content parsing and attachment handling. |
| `_process_call_log(self, message, data_source, tenant_id)` | Specialized call log processing with duration calculation and participant formatting. |
| `_process_meeting_event(self, message, data_source, tenant_id)` | Meeting event processing with metadata extraction and participant enrichment. |
| `_process_call_activity(self, message, data_source, tenant_id)` | Call activity processing for recordings and transcripts with regex-based content extraction. |
| `_process_message_reactions(self, message, data_source, tenant_id)` | Comprehensive reaction processing for emoticons and user interactions. |
| **Utility and Helper Methods** | |
| `_calculate_call_duration(self, start_time, end_time)` | Professional call duration calculation with multiple timestamp format support. |
| `_format_participant_info(self, participant)` | Advanced participant information formatting with contact name enrichment. |
| `_extract_meeting_attributes(self, message)` | Intelligent meeting metadata extraction from various content formats. |
| `_log_error(self, message)` | Structured error logging for debugging and monitoring. |
| **Content Processing Methods** | |
| `_clean_html(self, html_str, properties)` | Advanced HTML content cleaning with Reply/Forward handling and emoji extraction. |
| `_enrich_creator_with_name(self, creator_id)` | Contact name enrichment with "ID (Name)" format and fallback mechanisms. |
| `_safe_json_list(self, value)` | Robust JSON parsing with comprehensive error handling. |

---

## Typical Use Cases

* Investigating Teams chat communications in corporate or incident response cases.
* Analyzing call and meeting activity.
* Extracting and reviewing attachments, links, shared files, images, GIFs, and stickers.
* Cross-organizational analysis using Tenant IDs.
* Tracking user interactions through mentions and reactions.
* Detailed member analysis with contact information.
* Rich content analysis including HTML message formatting, emoji display, and Reply/Forward message threading.
* Media content investigation including inline images (AMSImage), blurHash images, GIFs, and stickers with proper URL extraction.
* Reconstructing the timeline of events related to a user.

---

## Support

For questions or improvements, please contact the module author or contribute via GitHub.