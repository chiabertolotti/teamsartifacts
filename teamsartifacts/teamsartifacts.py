# -*- coding: utf-8 -*-

"""
Contact: *the contact is currently hidden*

Autopsy Ingest Module – Microsoft Teams Data Visualization (from exported JSON)

This module parses exported Microsoft Teams Artifacts JSON files and extracts messages, calls, meetings, 
threads, members, mentions, reactions, contacts, and related metadata. It creates custom artifacts and 
attributes in Autopsy for detailed forensic analysis of Teams communications.

Supported artifacts:
- TSK_TEAMS_MESSAGE: Teams messages (text, HTML, replies, forwards)
- TSK_TEAMS_MSG_ATTACHMENT: Message attachments (links, files, AMSImage, GIFs, stickers)
- TSK_TEAMS_CALLLOG_CONV: Video and audio call logs (participants, IDs, timestamps)
- TSK_TEAMS_CALLLOG_MSG: Call activities (recordings, transcripts)
- TSK_TEAMS_EVENTCALL: Meeting events and metadata
- TSK_TEAMS_THREADINFO: General conversation threads (thread metadata)
- TSK_TEAMS_GROUP_CHAT: Group conversations (thread ID ends with @thread.v2)
- TSK_TEAMS_PRIVATE_CHAT: Private conversations (thread ID ends with @unq.gbl.spaces)
- TSK_TEAMS_TEAMS_CHAT: Teams conversations (thread ID ends with @thread.tacv2)
- TSK_TEAMS_THREAD_MEMBER: Thread members (detailed member information when available)
- TSK_TEAMS_CONTACTS: People/contacts information
- TSK_TEAMS_MENTION: Mentions in messages
- TSK_TEAMS_REACTION: Message reactions (emoticons, likes, etc.)

All artifacts include Tenant ID for cross-organizational analysis.
"""

import json
import os
import re
import calendar
import codecs
from datetime import datetime

from org.sleuthkit.autopsy.ingest import (
    DataSourceIngestModule,
    IngestModuleFactoryAdapter,
    IngestModule,
    IngestMessage,
    IngestServices,
)
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.datamodel import BlackboardArtifact, BlackboardAttribute
from org.sleuthkit.autopsy.datamodel import ContentUtils
from java.io import File

# Python 2/3 compatibility for string types
try:
    basestring
except NameError:
    basestring = str

try:
    unicode
except NameError:
    unicode = str

try:
    unichr
except NameError:
    def unichr(x):
        return chr(x)

# Constants
ARTIFACT_PREFIX = "Microsoft Teams"


class TeamsReplychainJSONParserFactory(IngestModuleFactoryAdapter):
    """
    Factory class for creating Microsoft Teams JSON parser instances.
    This class provides metadata about the parser module and creates parser instances.
    """
    
    moduleName = "Teams JSON Visualization"

    def getModuleDisplayName(self):
        """Return the display name shown in Autopsy's module list."""
        return self.moduleName

    def getModuleDescription(self):
        """Return a description of what this module does."""
        return "Data visualization of Microsoft Teams artefacts exported as JSON."

    def getModuleVersionNumber(self):
        """Return the version number of this module."""
        return "1.0"

    def isDataSourceIngestModuleFactory(self):
        """Indicate that this factory creates data source ingest modules."""
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        """Create and return a new parser instance."""
        return TeamsReplychainJSONParser()


class TeamsReplychainJSONParser(DataSourceIngestModule):
    """
    Main parser class for Microsoft Teams JSON artifacts.
    
    This class processes exported Teams JSON files and creates Autopsy artifacts
    for messages, calls, meetings, contacts, and other Teams data.
    """
    
    def startUp(self, context):
        """
        Initialize the parser and set up artifact types and attributes.
        
        Args:
            context: Ingest job context from Autopsy
        """
        self.context = context
        bb = Case.getCurrentCase().getServices().getBlackboard()

        # Initialize data storage maps
        self.conversation_tenant_map = {}  # Maps conversation ID to tenant ID
        self.contacts_map = {}  # Maps MRI to display name for participant lookups

        # Initialize artifact types for different Teams data categories
        self._initialize_artifact_types(bb)
        
        # Initialize attribute types for all artifacts
        self._initialize_attribute_types(bb)

    def _initialize_artifact_types(self, bb):
        """Initialize all custom artifact types for Teams data."""
        self.art_msg = bb.getOrAddArtifactType("TSK_TEAMS_MESSAGE", ARTIFACT_PREFIX + " Messages")
        self.art_att = bb.getOrAddArtifactType("TSK_TEAMS_MSG_ATTACHMENT", ARTIFACT_PREFIX + " Attachments")
        self.art_calllog_conv = bb.getOrAddArtifactType("TSK_TEAMS_CALLLOG_CONV", ARTIFACT_PREFIX + " Calls")
        self.art_calllog_msg = bb.getOrAddArtifactType("TSK_TEAMS_CALLLOG_MSG", ARTIFACT_PREFIX + " Call Activities")
        self.art_eventcall = bb.getOrAddArtifactType("TSK_TEAMS_EVENTCALL", ARTIFACT_PREFIX + " Meetings")
        self.art_thread = bb.getOrAddArtifactType("TSK_TEAMS_THREADINFO", ARTIFACT_PREFIX + " Conversations (other)")
        self.art_group_chat = bb.getOrAddArtifactType("TSK_TEAMS_GROUP_CHAT", ARTIFACT_PREFIX + " Group Chats")
        self.art_private_chat = bb.getOrAddArtifactType("TSK_TEAMS_PRIVATE_CHAT", ARTIFACT_PREFIX + " Private Chats")
        self.art_teams_chat = bb.getOrAddArtifactType("TSK_TEAMS_TEAMS_CHAT", ARTIFACT_PREFIX + " Channels")
        self.art_thread_member = bb.getOrAddArtifactType("TSK_TEAMS_THREAD_MEMBER", ARTIFACT_PREFIX + " Conversation Members")
        self.art_contacts = bb.getOrAddArtifactType("TSK_TEAMS_CONTACTS", ARTIFACT_PREFIX + " Contacts")
        self.art_mention = bb.getOrAddArtifactType("TSK_TEAMS_MENTION", ARTIFACT_PREFIX + " Mentions")
        self.art_reaction = bb.getOrAddArtifactType("TSK_TEAMS_REACTION", ARTIFACT_PREFIX + " Reactions")

    def _initialize_attribute_types(self, bb):
        """Initialize all custom attribute types for Teams artifacts."""
        self.attr = {}

        # Initialize different attribute groups
        self._init_member_attributes(bb)
        self._init_message_attributes(bb)
        self._init_reaction_attributes(bb)
        self._init_thread_attributes(bb)
        self._init_attachment_attributes(bb)
        self._init_call_attributes(bb)
        self._init_mention_attributes(bb)
        self._init_contact_attributes(bb)

    def _init_member_attributes(self, bb):
        """Initialize attributes for conversation members."""
        member_attributes = [
            ("TSK_TEAMS_MEMBER_ID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Members"),
        ]
        
        for name, vtype, desc in member_attributes:
            self.attr[name] = bb.getOrAddAttributeType(name, vtype, desc)

    def _init_message_attributes(self, bb):
        """Initialize attributes for Teams messages."""
        message_attributes = [
            ("TSK_TEAMS_MSG_ID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Message ID"),
            ("TSK_TEAMS_CONV_ID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Conversation ID"),
            ("TSK_TEAMS_SEQ_ID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Sequence ID"),
            ("TSK_TEAMS_TENANTID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Tenant ID"),
            ("TSK_TEAMS_CREATOR", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Message Author ID"),
            ("TSK_TEAMS_DISPLAY_NAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Author Display Name"),
            ("TSK_TEAMS_CONTENT", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Message Content"),
            ("TSK_TEAMS_MSG_TYPE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Message Category"),
            ("TSK_TEAMS_CLIENT_ARRIVAL", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, "Client Received Time"),
            ("TSK_TEAMS_ORIG_ARRIVAL", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, "Server Received Time"),
            ("TSK_TEAMS_HAS_ATTACHMENT", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Contains Attachments"),
            ("TSK_TEAMS_PROPERTIES", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Message Metadata"),
            ("TSK_TEAMS_EDIT_TIME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, "Last Modified Time"),
            ("TSK_TEAMS_COMPOSE_TIME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, "Composition Time"),
            ("TSK_TEAMS_DELETE_TIME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, "Deletion Time"),
            ("TSK_TEAMS_DRAFT_TIME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, "Draft Saved Time"),
        ]
        
        for name, vtype, desc in message_attributes:
            self.attr[name] = bb.getOrAddAttributeType(name, vtype, desc)

    def _init_reaction_attributes(self, bb):
        """Initialize attributes for message reactions."""
        reaction_attributes = [
            ("TSK_TEAMS_REACTION_MSG_ID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Message ID"),
            ("TSK_TEAMS_REACTION_SEQ_ID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Sequence ID"),
            ("TSK_TEAMS_REACTION_TYPE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Reaction Type"),
            ("TSK_TEAMS_REACTION_MRI", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Sender"),
            ("TSK_TEAMS_REACTION_TIME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, "Reaction Time")
        ]
        
        for name, vtype, desc in reaction_attributes:
            self.attr[name] = bb.getOrAddAttributeType(name, vtype, desc)

    def _init_thread_attributes(self, bb):
        """Initialize attributes for conversation threads."""
        thread_attributes = [
            ("TSK_TEAMS_THREAD_ID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Thread ID"),
            ("TSK_TEAMS_THREAD_TYPE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Thread Type"),
            ("TSK_TEAMS_TEAMID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Team ID"),
            ("TSK_TEAMS_TENANTID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Tenant ID"),
            ("TSK_TEAMS_TOPIC", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Conversation Topic"),
            ("TSK_TEAMS_HASDRAFT", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Has Unsent Draft"),
            ("TSK_TEAMS_MEMBER_ID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Thread Participants"),
            ("TSK_TEAMS_TOPIC_DESCRIP", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Thread Description"),
            ("TSK_TEAMS_CREATOR", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Thread Creator ID"),
            ("TSK_TEAMS_CREATEDAT", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Thread Creation Time"),
        ]
        
        for name, vtype, desc in thread_attributes:
            self.attr[name] = bb.getOrAddAttributeType(name, vtype, desc)

    def _init_attachment_attributes(self, bb):
        """Initialize attributes for message attachments."""
        attachment_attributes = [
            ("TSK_TEAMS_ATT_URL", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Attachment URL"),
            ("TSK_TEAMS_ATT_NAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Attachment Name"),
            ("TSK_TEAMS_ATT_TYPE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Attachment Type"),
        ]
        
        for name, vtype, desc in attachment_attributes:
            self.attr[name] = bb.getOrAddAttributeType(name, vtype, desc)

    def _init_call_attributes(self, bb):
        """Initialize attributes for call logs and activities."""
        call_attributes = [
            ("TSK_TEAMS_CALLLOG_STATUS", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Call Status"),
            ("TSK_TEAMS_CALLLOG_ORIGINALNAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Call Recording Name"),
            ("TSK_TEAMS_CALLLOG_INITIATOR", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Call Initiator"),
            ("TSK_TEAMS_CALLLOG_TERMINATOR", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Call Terminator"),
            ("TSK_TEAMS_CALLLOG_CALLID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Call Session ID"),
            ("TSK_TEAMS_CALLLOG_DURATION", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Call Duration"),
            ("TSK_TEAMS_CALLLOG_TIMESTAMP", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Call Start Time"),
            ("TSK_TEAMS_CALLLOG_MEETING_ORGID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Meeting Organizer ID"),
        ]
        
        for name, vtype, desc in call_attributes:
            self.attr[name] = bb.getOrAddAttributeType(name, vtype, desc)

    def _init_mention_attributes(self, bb):
        """Initialize attributes for mentions in messages."""
        mention_attributes = [
            ("TSK_TEAMS_MENTION_CONV_ID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Conversation ID"),
            ("TSK_TEAMS_MENTION_MRI", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Mentioned User ID"),
            ("TSK_TEAMS_MENTION_TYPE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Mention Category"),
            ("TSK_TEAMS_MENTION_DISPLAYNAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Mentioned User Name")
        ]
        
        for name, vtype, desc in mention_attributes:
            self.attr[name] = bb.getOrAddAttributeType(name, vtype, desc)

    def _init_contact_attributes(self, bb):
        """Initialize attributes for contact information."""
        contact_attributes = [
            ("TSK_TEAMS_CONTACT_DISPLAYNAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Contact Display Name"),
            ("TSK_TEAMS_CONTACT_EMAIL", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Contact Email Address"),
            ("TSK_TEAMS_CONTACT_MRI", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Microsoft Resource Identifier"),
            ("TSK_TEAMS_CONTACT_TENANT", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Organization Tenant"),
            ("TSK_TEAMS_CONTACT_OBJECT_ID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Azure AD Object ID"),
            ("TSK_TEAMS_CONTACT_USER_TYPE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Account Type"),
            ("TSK_TEAMS_CONTACT_GIVEN_NAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "First Name"),
            ("TSK_TEAMS_CONTACT_SURNAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Last Name"),
            ("TSK_TEAMS_CONTACT_UPN", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "User Principal Name")
        ]
        
        for name, vtype, desc in contact_attributes:
            self.attr[name] = bb.getOrAddAttributeType(name, vtype, desc)

    def process(self, dataSource, progressBar):
        """
        Main processing method that handles Teams JSON files.
        
        Args:
            dataSource: The data source to process
            progressBar: Progress bar for user feedback
            
        Returns:
            IngestModule.ProcessResult: Processing result status
        """
        fileMgr = Case.getCurrentCase().getServices().getFileManager()
        jsonFiles = fileMgr.findFiles(dataSource, "%.json")
        
        # Categorize JSON files by type for proper processing order
        conversationFiles, peopleFiles, otherFiles = self._categorize_json_files(jsonFiles)
        
        # Process files in specific order: people first (for contact mapping), then conversations, then others
        return self._process_files_in_sequence(conversationFiles, peopleFiles, otherFiles)

    def _categorize_json_files(self, jsonFiles):
        """
        Categorize JSON files into conversation, people, and other files.
        
        Args:
            jsonFiles: List of JSON files found in the data source
            
        Returns:
            tuple: (conversationFiles, peopleFiles, otherFiles)
        """
        conversationFiles = []
        peopleFiles = []
        otherFiles = []
        
        for jsonFile in jsonFiles:
            filename = jsonFile.getName()
            if filename == "output_conversations.json":
                conversationFiles.append(jsonFile)
            elif filename == "output_people.json":
                peopleFiles.append(jsonFile)
            else:
                otherFiles.append(jsonFile)
                
        return conversationFiles, peopleFiles, otherFiles

    def _process_files_in_sequence(self, conversationFiles, peopleFiles, otherFiles):
        """
        Process files in the correct sequence to ensure proper data relationships.
        
        Args:
            conversationFiles: List of conversation JSON files
            peopleFiles: List of people JSON files  
            otherFiles: List of other JSON files
            
        Returns:
            IngestModule.ProcessResult: Processing result status
        """
        # Process people files first to populate contact mapping
        for jsonFile in peopleFiles:
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK
            self._process_single_file(jsonFile)
        
        # Process conversation files after contacts are loaded
        for jsonFile in conversationFiles:
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK
            self._process_single_file(jsonFile)
        
        # Process remaining files
        for jsonFile in otherFiles:
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK
            self._process_single_file(jsonFile)
        
        return IngestModule.ProcessResult.OK

    def _process_single_file(self, jsonFile):
        """
        Process a single JSON file by extracting it to temp directory and parsing.
        
        Args:
            jsonFile: The JSON file object to process
        """
        tmpDir = Case.getCurrentCase().getTempDirectory()
        localJSON = os.path.join(tmpDir, jsonFile.getName())
        ContentUtils.writeToFile(jsonFile, File(localJSON))
        self._parse_json(localJSON, jsonFile)

    def _parse_json(self, json_path, jsonFile):
        """
        Parse a JSON file and create appropriate artifacts based on file type.
        
        Args:
            json_path: Local path to the JSON file
            jsonFile: Original file object from Autopsy
        """
        bb = Case.getCurrentCase().getServices().getBlackboard()
        basename = os.path.basename(json_path)
        
        # Initialize counters for different artifact types
        counters = {
            'messages': 0,
            'calls_conv': 0,
            'calls_msg': 0,
            'meetings': 0,
            'threads': 0,
            'contacts': 0
        }
        
        try:
            # Load and parse JSON data
            with codecs.open(json_path, "r", "utf-8") as f:
                records = json.load(f)
            
            # Process based on file type
            if basename == "output_conversations.json":
                counters['threads'] = self._process_conversations(records, jsonFile, bb)
            elif basename == "output_people.json":
                counters['contacts'] = self._process_people(records, jsonFile, bb)
            else:
                # Process other JSON files (messages, calls, etc.)
                counters = self._process_message_data(records, jsonFile, bb)
            
            # Post processing results message
            self._post_processing_message(basename, counters)
                    
        except Exception as e:
            self._handle_parsing_error(json_path, e)

    def _process_conversations(self, records, jsonFile, bb):
        """
        Process conversation data from output_conversations.json.
        
        Args:
            records: JSON records to process
            jsonFile: File object from Autopsy
            bb: Blackboard instance
            
        Returns:
            int: Number of threads processed
        """
        total_threads = 0
        
        for rec in records:
            value_obj = rec.get("value", {})
            tenantId = rec.get("tenant_id", None)
            
            if isinstance(value_obj, dict) and "value" in value_obj:
                thread_val = value_obj["value"]
                
                # Extract thread data safely
                threadId = self._safe_string_extract(thread_val.get("id"))
                threadType = self._safe_string_extract(thread_val.get("type"))
                teamId = self._safe_string_extract(thread_val.get("teamId"))
                
                # Store tenant mapping for this conversation
                if threadId and tenantId:
                    self.conversation_tenant_map[threadId] = tenantId
                
                # Process thread properties
                thread_data = self._extract_thread_data(thread_val)
                
                # Create appropriate artifact based on thread type
                artifact_type = self._determine_thread_artifact_type(threadId)
                
                # Create and populate artifact
                art = jsonFile.newArtifact(artifact_type.getTypeID())
                self._populate_thread_artifact(art, threadId, threadType, teamId, tenantId, thread_data)
                bb.indexArtifact(art)
                total_threads += 1
        
        return total_threads

    def _process_people(self, records, jsonFile, bb):
        """
        Process people/contacts data from output_people.json.
        
        Args:
            records: JSON records to process
            jsonFile: File object from Autopsy
            bb: Blackboard instance
            
        Returns:
            int: Number of contacts processed
        """
        total_contacts = 0
        
        for rec in records:
            if isinstance(rec, dict) and "value" in rec:
                contact_data = rec["value"]
                
                # Extract contact information
                mri = contact_data.get("mri", "")
                displayName = contact_data.get("displayname", "")
                
                # Store in contacts map for name enrichment
                if mri and displayName:
                    self.contacts_map[mri] = displayName
                
                # Create contact artifact
                art = jsonFile.newArtifact(self.art_contacts.getTypeID())
                self._populate_contact_artifact(art, contact_data)
                bb.indexArtifact(art)
                total_contacts += 1
        
        return total_contacts

    def _process_message_data(self, records, jsonFile, bb):
        """
        Process message data from various JSON files.
        
        Args:
            records: JSON records to process
            jsonFile: File object from Autopsy
            bb: Blackboard instance
            
        Returns:
            dict: Counters for different artifact types
        """
        counters = {
            'messages': 0,
            'calls_conv': 0,
            'calls_msg': 0,
            'meetings': 0
        }
        
        for rec in records:
            if self.context.isJobCancelled():
                break
                
            value_obj = rec.get("value", {})
            if not isinstance(value_obj, dict):
                continue
                
            main_value = value_obj.get("value", {})
            if not isinstance(main_value, dict):
                continue
                
            conversation_id = main_value.get("conversationId")
            message_map = main_value.get("messageMap", {})
            
            if not conversation_id or not isinstance(message_map, dict):
                continue
            
            # Process each message in the message map
            for msg in message_map.values():
                msg_counters = self._process_single_message(msg, conversation_id, jsonFile, bb)
                for key, value in msg_counters.items():
                    counters[key] += value
        
        return counters

    def _process_single_message(self, msg, conversation_id, jsonFile, bb):
        """
        Process a single message and create appropriate artifacts.
        
        Args:
            msg: Message data dictionary
            conversation_id: ID of the conversation this message belongs to
            jsonFile: File object from Autopsy
            bb: Blackboard instance
            
        Returns:
            dict: Counters for artifacts created
        """
        counters = {'messages': 0, 'calls_conv': 0, 'calls_msg': 0, 'meetings': 0}
        
        msg_type = msg.get("messageType", "")
        
        # Handle different message types
        if conversation_id == "48:calllogs":
            counters['calls_conv'] += self._process_call_log(msg, conversation_id, jsonFile, bb)
        elif msg_type in ["RichText/Media_CallRecording", "RichText/Media_CallTranscript"]:
            counters['calls_msg'] += self._process_call_activity(msg, conversation_id, jsonFile, bb)
        elif msg_type == "Event/Call":
            counters['meetings'] += self._process_meeting_event(msg, conversation_id, jsonFile, bb)
        elif msg_type in ["Text", "RichText/Html"]:
            counters['messages'] += self._process_regular_message(msg, conversation_id, jsonFile, bb)
        
        # Always process reactions and mentions regardless of message type
        self._process_message_reactions(msg, conversation_id, jsonFile, bb)
        
        return counters

    def _process_regular_message(self, msg, conversation_id, jsonFile, bb):
        """
        Process a regular text or HTML message.
        
        Args:
            msg: Message data dictionary
            conversation_id: ID of the conversation
            jsonFile: File object from Autopsy
            bb: Blackboard instance
            
        Returns:
            int: Number of messages processed (0 or 1)
        """
        # Extract message data
        seq_id = msg.get("sequenceId")
        content = msg.get("content", "")
        msg_id = msg.get("id")
        creator = msg.get("creator")
        display_name = msg.get("imDisplayName")
        msg_type = msg.get("messageType")
        orig_arrival = msg.get("originalArrivalTime")
        properties = msg.get("properties", {})
        
        # Convert to safe unicode strings
        content = self._safe_unicode(content)
        msg_id = self._safe_unicode(msg_id)
        creator = self._safe_unicode(creator)
        display_name = self._safe_unicode(display_name)
        msg_type = self._safe_unicode(msg_type)
        
        # Process HTML content if needed
        if msg_type == "RichText/Html":
            content = self._clean_html(content, properties)
            
            # Check for AMSImage content and create attachment if found
            if self._has_ams_image_content(content):
                self._create_ams_image_attachment(content, conversation_id, msg_id, jsonFile, bb)
        
        # Handle empty content
        if not content and isinstance(properties, dict) and "files" in properties:
            content = self._extract_file_names_as_content(properties["files"])
        
        # Convert timestamps
        orig_arrival_ts = self._convert_timestamp(orig_arrival, for_datetime_attr=True)
        
        # Extract timestamps from properties
        edit_time_val = self._extract_timestamp_from_properties(properties, "edittime")
        compose_time_val = self._extract_timestamp_from_properties(properties, "composetime")
        delete_time_val = self._extract_timestamp_from_properties(properties, "deletetime")
        draft_time_val = self._extract_timestamp_from_properties(properties, "drafttimestamp")
        
        # Process properties and attachments
        properties_json = self._serialize_properties(properties)
        link_urls, file_min, mention_min = self._extract_props(properties if isinstance(properties, dict) else {})
        
        # Determine if message has attachments
        has_attachment = "yes" if link_urls or file_min or self._has_blur_hash(properties) else "no"
        
        # Get tenant ID for this conversation
        tenant_id = self.conversation_tenant_map.get(conversation_id, "")
        
        # Enrich creator with contact name if available
        enriched_creator = self._enrich_creator_with_name(creator) if creator else ""
        
        # Create message artifact
        art = jsonFile.newArtifact(self.art_msg.getTypeID())
        
        # Populate message attributes
        art.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_TENANTID"], ARTIFACT_PREFIX, tenant_id))
        art.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_CONV_ID"], ARTIFACT_PREFIX, conversation_id))
        art.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_MSG_ID"], ARTIFACT_PREFIX, msg_id))
        art.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_SEQ_ID"], ARTIFACT_PREFIX, str(seq_id)))
        art.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_CREATOR"], ARTIFACT_PREFIX, enriched_creator))
        art.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_DISPLAY_NAME"], ARTIFACT_PREFIX, display_name if display_name else ""))
        art.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_CONTENT"], ARTIFACT_PREFIX, content))
        art.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_MSG_TYPE"], ARTIFACT_PREFIX, msg_type))
        art.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_HAS_ATTACHMENT"], ARTIFACT_PREFIX, has_attachment))
        art.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_PROPERTIES"], ARTIFACT_PREFIX, properties_json))
        
        # Add timestamps
        if orig_arrival_ts:
            art.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_ORIG_ARRIVAL"], ARTIFACT_PREFIX, orig_arrival_ts))
        if edit_time_val:
            art.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_EDIT_TIME"], ARTIFACT_PREFIX, edit_time_val))
        if compose_time_val:
            art.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_COMPOSE_TIME"], ARTIFACT_PREFIX, compose_time_val))
        if delete_time_val:
            art.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_DELETE_TIME"], ARTIFACT_PREFIX, delete_time_val))
        if draft_time_val:
            art.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_DRAFT_TIME"], ARTIFACT_PREFIX, draft_time_val))
        
        bb.indexArtifact(art)
        
        # Create attachment artifacts
        for url in link_urls:
            self._make_attachment(bb, jsonFile, conversation_id, msg_id, url, "", "link", tenant_id)
            
        for file_info in file_min:
            self._make_attachment(bb, jsonFile, conversation_id, msg_id, "", 
                                file_info.get("fileName", ""), file_info.get("fileType", ""), tenant_id)
        
        # Create mention artifacts
        for mention in mention_min:
            self._make_mention(bb, jsonFile, conversation_id, msg_id, 
                             mention.get("mri", ""), mention.get("mentionType", ""), 
                             mention.get("displayName", ""), tenant_id)
        
        return 1

    # Utility methods for data processing
    
    def _safe_string_extract(self, val):
        """Safely extract string value from potentially mixed data types."""
        if val is None:
            return ""
        if isinstance(val, basestring):
            return val.strip()
        if isinstance(val, dict):
            return ""
        return unicode(val)

    def _safe_unicode(self, val):
        """Safely convert value to unicode string."""
        if val is None:
            return u""
        if isinstance(val, unicode):
            return val
        if isinstance(val, str):
            try:
                return val.decode('utf-8')
            except UnicodeDecodeError:
                return val.decode('utf-8', 'replace')
        return unicode(val)

    def _convert_timestamp(self, val, for_datetime_attr=True):
        """
        Convert timestamp to appropriate format.
        
        Args:
            val: Timestamp value (string or numeric)
            for_datetime_attr: If True, return numeric timestamp for DATETIME attributes
                              If False, return formatted string for STRING attributes
        
        Returns:
            Converted timestamp or None/empty string if conversion fails
        """
        if not val:
            return None if for_datetime_attr else u""
        
        try:
            # Handle ISO8601 strings
            if isinstance(val, basestring) and ("T" in val and ("-" in val or ":" in val)):
                val_clean = val.rstrip("Z")  # Remove trailing Z if present
                try:
                    # Try with microseconds first
                    if "." in val_clean:
                        dt = datetime.strptime(val_clean[:26], "%Y-%m-%dT%H:%M:%S.%f")
                    else:
                        dt = datetime.strptime(val_clean[:19], "%Y-%m-%dT%H:%M:%S")
                    
                    if for_datetime_attr:
                        return calendar.timegm(dt.timetuple())  # Numeric timestamp
                    else:
                        return dt.strftime("%Y-%m-%d %H:%M:%S")  # Formatted string
                except Exception:
                    # Fallback for string format
                    if not for_datetime_attr:
                        return val_clean[:19].replace("T", " ")
                    return None
            
            # Handle numeric timestamps
            v = float(val)
            if v > 9999999999:
                v = v / 1000.0
            
            if for_datetime_attr:
                return int(v)  # Numeric timestamp
            else:
                dt = datetime.utcfromtimestamp(v)
                return dt.strftime("%Y-%m-%d %H:%M:%S")  # Formatted string
                
        except Exception:
            if for_datetime_attr:
                return None
            else:
                return unicode(val) if val else u""

    def _has_ams_image_content(self, content):
        """Check if content contains AMSImage indicators."""
        if not content:
            return False
        return "AMSImage" in content or "amsimage" in content.lower()

    def _create_ams_image_attachment(self, content, conversation_id, msg_id, jsonFile, bb):
        """Create attachment artifact for AMSImage content."""
        tenant_id = self.conversation_tenant_map.get(conversation_id, "")
        self._make_attachment(bb, jsonFile, conversation_id, msg_id, "", 
                            "AMSImage", "image", tenant_id)

    def _has_blur_hash(self, properties):
        """Check if properties contain blurHash indicating image attachment."""
        if not isinstance(properties, dict):
            return False
        blur_hash = properties.get("blurHash")
        if blur_hash:
            blur_hash_list = self._safe_json_list(blur_hash)
            return isinstance(blur_hash_list, list) and len(blur_hash_list) > 0
        return False

    def _extract_file_names_as_content(self, files_data):
        """Extract file names from files data to use as content."""
        files_list = self._safe_json_list(files_data)
        if files_list:
            file_names = []
            for f in files_list:
                if isinstance(f, dict):
                    name = f.get("fileName", f.get("title", ""))
                    if name:
                        file_names.append(name)
            return " | ".join(file_names) if file_names else ""
        return ""

    def _extract_timestamp_from_properties(self, properties, timestamp_key):
        """Extract and convert timestamp from properties dictionary."""
        if isinstance(properties, dict) and timestamp_key in properties:
            return self._convert_timestamp(properties[timestamp_key], for_datetime_attr=True)
        return None

    def _serialize_properties(self, properties):
        """Serialize properties dictionary to JSON string."""
        try:
            return json.dumps(properties, ensure_ascii=False, separators=(',', ':'))
        except Exception:
            return "{}"

    def _extract_props(self, props):
        """Extract links, files, and mentions from properties."""
        links_raw = props.get("links")
        files_raw = props.get("files")
        mentions_raw = props.get("mentions")
        
        links = self._safe_json_list(links_raw)
        files = self._safe_json_list(files_raw)
        mentions = self._safe_json_list(mentions_raw)
        
        link_urls = [l.get("url", l.get("itemid", "")) for l in links 
                    if isinstance(l, dict) and l.get("url")]
        
        file_min = [
            {"fileName": f.get("fileName", f.get("title", "")), 
             "fileType": f.get("fileType", f.get("type", ""))}
            for f in files if isinstance(f, dict)
        ]
        
        mention_min = []
        
        # Group mentions by MRI to handle split names
        mention_groups = {}
        for m in mentions:
            if isinstance(m, dict):
                mri = m.get("mri", "")
                mention_type = m.get("mentionType", "")
                display_name = m.get("displayName", "")
                
                if mri:  # Only process if MRI exists
                    if mri not in mention_groups:
                        mention_groups[mri] = {
                            "mri": mri,
                            "mentionType": mention_type,
                            "displayName_parts": []
                        }
                    mention_groups[mri]["displayName_parts"].append(display_name)
        
        # Reconstruct full names by joining display name parts
        for mri, group in mention_groups.items():
            name_parts = [part.strip() for part in group["displayName_parts"] if part.strip()]
            if name_parts:
                full_name = " ".join(name_parts)
                full_name = full_name.replace(" ,", ",").replace("( ", "(").replace(" )", ")")
                
                mention_min.append({
                    "mri": group["mri"],
                    "mentionType": group["mentionType"],
                    "displayName": full_name
                })
        
        return link_urls, file_min, mention_min

    def _safe_json_list(self, value):
        """Safe JSON list parser."""
        if not value:
            return []
        if isinstance(value, list):
            return value
        if isinstance(value, basestring):
            try:
                parsed = json.loads(value)
                return parsed if isinstance(parsed, list) else []
            except Exception:
                return []
        return []

    def _make_attachment(self, bb, jsonFile, conv_id, msg_id, url, name, ftype, tenant_id=""):
        """Create attachment artifact."""
        art = jsonFile.newArtifact(self.art_att.getTypeID())
        art.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_TENANTID"], ARTIFACT_PREFIX, tenant_id))
        art.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_CONV_ID"], ARTIFACT_PREFIX, conv_id))
        art.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_MSG_ID"], ARTIFACT_PREFIX, msg_id))
        if url:
            art.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_ATT_URL"], ARTIFACT_PREFIX, url))
        art.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_ATT_NAME"], ARTIFACT_PREFIX, name))
        if ftype:
            art.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_ATT_TYPE"], ARTIFACT_PREFIX, ftype))
        bb.indexArtifact(art)

    def _make_mention(self, bb, jsonFile, conv_id, msg_id, mri, mention_type, display_name, tenant_id=""):
        """Create mention artifact."""
        art = jsonFile.newArtifact(self.art_mention.getTypeID())
        art.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_TENANTID"], ARTIFACT_PREFIX, tenant_id))
        art.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_MENTION_CONV_ID"], ARTIFACT_PREFIX, conv_id))
        art.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_MSG_ID"], ARTIFACT_PREFIX, msg_id))
        art.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_MENTION_MRI"], ARTIFACT_PREFIX, mri))
        art.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_MENTION_TYPE"], ARTIFACT_PREFIX, mention_type))
        art.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_MENTION_DISPLAYNAME"], ARTIFACT_PREFIX, display_name))
        bb.indexArtifact(art)

    def _unescape_html(self, text):
        """Unescape HTML entities."""
        if not text:
            return ""
        text = text.replace("&amp;", "&")
        text = text.replace("&lt;", "<")
        text = text.replace("&gt;", ">")
        text = text.replace("&quot;", "\"")
        text = text.replace("&#39;", "'")
        return text

    def _clean_html(self, html_str, properties=None):
        """Clean HTML content and extract relevant information."""
        try:
            unichr_fn = unichr
        except NameError:
            unichr_fn = chr
            
        def bold_unicode(text):
            """Convert text to bold unicode characters."""
            bold_map = {}
            for i in range(26):
                bold_map[chr(ord('A')+i)] = unichr_fn(0x1D400 + i)
            for i in range(26):
                bold_map[chr(ord('a')+i)] = unichr_fn(0x1D41A + i)
            for i in range(10):
                bold_map[chr(ord('0')+i)] = unichr_fn(0x1D7CE + i)
            return u''.join(bold_map.get(c, c) for c in text)
        
        if not html_str:
            return u""
        
        # Handle simple link cases
        link_match = re.match(r'\s*<p>?\s*<a [^>]*href="([^"]+)"[^>]*>[^<]+</a>\s*</p>?\s*$', 
                             html_str.strip(), re.IGNORECASE)
        if not link_match:
            link_match = re.match(r'\s*<a [^>]*href="([^"]+)"[^>]*>[^<]+</a>\s*$', 
                                 html_str.strip(), re.IGNORECASE)
        if link_match:
            return link_match.group(1)
        
        # Process blockquotes for replies and forwards
        blockquote_reply = re.search(
            r'<blockquote[^>]*?(?:itemscope[^>]*?)?itemtype="http://schema.skype.com/Reply"[^>]*>([\s\S]*?)</blockquote>', 
            html_str, re.IGNORECASE)
        blockquote_forward = re.search(
            r'<blockquote[^>]*?(?:itemscope[^>]*?)?itemtype="http://schema.skype.com/Forward"[^>]*>([\s\S]*?)</blockquote>', 
            html_str, re.IGNORECASE)
        
        if blockquote_reply or blockquote_forward:
            if blockquote_reply:
                return self._process_reply_blockquote(blockquote_reply, html_str, bold_unicode)
            elif blockquote_forward:
                return self._process_forward_blockquote(blockquote_forward, html_str, bold_unicode, properties)
        
        # Process regular HTML content
        return self._process_regular_html(html_str)

    def _process_reply_blockquote(self, blockquote_match, html_str, bold_unicode):
        """Process reply blockquote content."""
        quoted_html = blockquote_match.group(1)
        before_blockquote = html_str[:blockquote_match.start()].strip()
        after_blockquote = html_str[blockquote_match.end():]
        
        sender_match = re.search(r'<strong[^>]*>([^<]+)</strong>', quoted_html, re.IGNORECASE)
        sender = sender_match.group(1).strip() if sender_match else None
        
        quoted_no_sender = re.sub(r'<strong[^>]*>[^<]+</strong>', '', quoted_html, flags=re.IGNORECASE)
        quoted = self._clean_html(quoted_no_sender)
        reply = self._clean_html(after_blockquote)
        
        if sender:
            span_id_match = re.search(r'<span[^>]*itemid\s*=\s*"([^"]+)"', quoted_html, re.IGNORECASE)
            itemid = span_id_match.group(1) if span_id_match else None
            
            if itemid:
                contact_name = self._get_contact_name_by_id(itemid)
                if contact_name:
                    result = bold_unicode(u"In reply to {} ({}):".format(sender, contact_name)) + " " + quoted.strip() + u"\n\n" + reply.strip()
                else:
                    result = bold_unicode(u"In reply to {}:".format(sender)) + " " + quoted.strip() + u"\n\n" + reply.strip()
            else:
                result = bold_unicode(u"In reply to {}:".format(sender)) + " " + quoted.strip() + u"\n\n" + reply.strip()
        else:
            result = bold_unicode(u"In reply to message") + ": " + quoted.strip() + u"\n\n" + reply.strip()
        
        # Add content before blockquote if present
        if before_blockquote:
            before_clean = self._clean_html(before_blockquote)
            result = before_clean.strip() + "\n\n" + result
            
        return result.strip()

    def _process_forward_blockquote(self, blockquote_match, html_str, bold_unicode, properties):
        """Process forward blockquote content."""
        quoted_html = blockquote_match.group(1)
        before_blockquote = html_str[:blockquote_match.start()].strip()
        after_blockquote = html_str[blockquote_match.end():]
        
        quoted = self._clean_html(quoted_html)
        reply = self._clean_html(after_blockquote)
        
        # Extract info from originalMessageContext if available
        info = u""
        if properties and isinstance(properties, dict):
            ctx = properties.get("originalMessageContext")
            if ctx and isinstance(ctx, dict):
                orig_sender = ctx.get("sender", "")
                orig_time = ctx.get("clientArrivalTime", "")
                if orig_sender or orig_time:
                    time_str = self._convert_timestamp(orig_time, for_datetime_attr=False) if orig_time else ""
                    info = u"Original: {} {}".format(orig_sender, time_str).strip() + u"\n"
        
        result = info + bold_unicode(u"Forwarded message:") + " " + quoted.strip()
        
        # Add content before blockquote if present
        if before_blockquote:
            before_clean = self._clean_html(before_blockquote)
            result = before_clean.strip() + "\n\n" + result
            
        if reply.strip():
            result += u"\n\n" + reply.strip()
            
        return result.strip()

    def _process_regular_html(self, html_str):
        """Process regular HTML content by removing tags and cleaning up."""
        # Extract all hrefs from <a href=...>
        hrefs = re.findall(r'<a [^>]*href="([^"]+)"[^>]*>', html_str, re.IGNORECASE)
        
        # Replace each <a ...>...</a> with just the href
        html_str_links_to_href = re.sub(r'<a [^>]*href="([^"]+)"[^>]*>[^<]*</a>', 
                                       r'\1', html_str, flags=re.IGNORECASE)
        
        # Remove all tags, convert HTML to text
        html_str_no_tags = html_str_links_to_href.replace("<br>", "\n").replace("<br/>", "\n").replace("<br />", "\n")
        html_str_no_tags = re.sub(r"</p\s*>", "\n", html_str_no_tags)
        html_str_no_tags = re.sub(r"<[^>]+>", "", html_str_no_tags)
        
        # Decode HTML entities
        html_str_no_tags = self._unescape_html(html_str_no_tags)
        
        # Decode literal escape sequences
        html_str_no_tags = re.sub(r"\\(['\"])", r"\1", html_str_no_tags)
        html_str_no_tags = re.sub(r"\\(['\"])", r"\1", html_str_no_tags)
        
        # Clean up whitespace characters
        html_str_no_tags = html_str_no_tags.replace(u"\xa0", " ")
        html_str_no_tags = html_str_no_tags.replace("&nbsp;", " ")
        html_str_no_tags = html_str_no_tags.replace("\\xa0", " ")
        html_str_no_tags = re.sub(u"[\u00A0\u2007\u202F]", " ", html_str_no_tags)
        html_str_no_tags = html_str_no_tags.replace("\\r\\n", "\n").replace("\r\n", "\n").replace("\\n", "\n")
        html_str_no_tags = html_str_no_tags.strip()
        
        # Add hrefs at the end if not already present
        if hrefs:
            hrefs_to_add = [h for h in hrefs if h not in html_str_no_tags]
            if hrefs_to_add:
                if html_str_no_tags:
                    return html_str_no_tags + "\n" + "\n".join(hrefs_to_add)
                else:
                    return "\n".join(hrefs_to_add)
        
        return html_str_no_tags

    def _get_contact_name_by_id(self, participant_id):
        """Get contact display name by participant ID."""
        if not participant_id or not self.contacts_map:
            return None
            
        # Try direct lookup first
        if participant_id in self.contacts_map:
            return self.contacts_map[participant_id]
            
        # Try partial matches for MRI format
        participant_id_str = str(participant_id).strip()
        for contact_id, display_name in self.contacts_map.items():
            if contact_id and participant_id_str and (
                contact_id == participant_id_str or
                participant_id_str in contact_id or
                contact_id in participant_id_str
            ):
                return display_name
                
        return None

    def _enrich_creator_with_name(self, creator_id):
        """Enrich creator ID with contact name in parentheses."""
        if not creator_id:
            return creator_id
            
        contact_name = self._get_contact_name_by_id(creator_id)
        if contact_name:
            return "{} ({})".format(creator_id, contact_name)
        else:
            return creator_id

    def _post_processing_message(self, basename, counters):
        """Post processing completion message."""
        total_processed = sum(counters.values())
        if total_processed > 0:
            IngestServices.getInstance().postMessage(
                IngestMessage.createMessage(
                    IngestMessage.MessageType.DATA,
                    "Teams JSON Parser",
                    "Processed {} items from {}".format(total_processed, basename),
                )
            )

    def _handle_parsing_error(self, json_path, error):
        """Handle parsing errors with robust error message formatting."""
        try:
            err_msg = u"Error parsing {}: {}".format(os.path.basename(json_path), str(error))
            if hasattr(err_msg, 'encode'):
                err_msg = err_msg.encode('utf-8', 'replace').decode('utf-8')
        except Exception:
            err_msg = "Error parsing file (error in error message encoding)"
            
        IngestServices.getInstance().postMessage(
            IngestMessage.createMessage(
                IngestMessage.MessageType.ERROR,
                "Teams JSON Parser",
                err_msg,
            )
        )

    def _calculate_call_duration(self, start_time, end_time):
        """Calculate call duration from start and end timestamps."""
        try:
            def parse_timestamp_to_seconds(timestamp):
                """Convert timestamp to seconds since epoch."""
                if isinstance(timestamp, basestring) and ("T" in timestamp and ("-" in timestamp or ":" in timestamp)):
                    timestamp_clean = timestamp.rstrip("Z")  # Remove trailing Z if present
                    try:
                        # Try with microseconds first
                        if "." in timestamp_clean:
                            dt = datetime.strptime(timestamp_clean[:26], "%Y-%m-%dT%H:%M:%S.%f")
                        else:
                            dt = datetime.strptime(timestamp_clean[:19], "%Y-%m-%dT%H:%M:%S")
                        return calendar.timegm(dt.timetuple())
                    except Exception:
                        return None
                else:
                    # Handle numeric timestamps
                    v = float(timestamp)
                    if v > 9999999999:
                        v = v / 1000.0
                    return int(v)
            
            start_seconds = parse_timestamp_to_seconds(start_time)
            end_seconds = parse_timestamp_to_seconds(end_time)
            
            if start_seconds and end_seconds:
                duration_seconds = end_seconds - start_seconds
                if duration_seconds >= 0:
                    # Format duration as HH:MM:SS
                    hours = duration_seconds // 3600
                    minutes = (duration_seconds % 3600) // 60
                    seconds = duration_seconds % 60
                    return "{:02d}:{:02d}:{:02d}".format(int(hours), int(minutes), int(seconds))
        except Exception:
            return None
        
        return None

    def _format_participant_info(self, participant):
        """Format participant information into readable string."""
        if not isinstance(participant, dict):
            return str(participant) if participant else ""
        
        participant_id = participant.get("id", "")
        display_name = participant.get("displayName", "")
        
        # Enrich with contact name if available
        if participant_id:
            enriched_id = self._enrich_creator_with_name(participant_id)
            if display_name and display_name != participant_id:
                return "{} [{}]".format(enriched_id, display_name)
            else:
                return enriched_id
        
        return display_name if display_name else ""

    def _format_participants_list(self, participants):
        """Format participants list into readable string."""
        if not participants:
            return ""
        
        if isinstance(participants, list):
            formatted_participants = []
            for p in participants:
                formatted = self._format_participant_info(p)
                if formatted:
                    formatted_participants.append(formatted)
            return "; ".join(formatted_participants)
        
        return str(participants)

    def _enrich_participants_with_names(self, participants_data):
        """
        Enrich participants data with display names from contacts.
        Handles both list and dict formats and adds names in parentheses.
        """
        if not participants_data or not self.contacts_map:
            return participants_data
            
        try:
            # Handle list of participants
            if isinstance(participants_data, list):
                enriched_list = []
                for participant in participants_data:
                    if isinstance(participant, dict):
                        enriched_participant = dict(participant)  # Create a copy
                        participant_id = participant.get("id") or participant.get("mri") or participant.get("participantId")
                        if participant_id:
                            contact_name = self._get_contact_name_by_id(participant_id)
                            if contact_name:
                                enriched_participant["enriched_name"] = contact_name
                        enriched_list.append(enriched_participant)
                    elif isinstance(participant, basestring):
                        # Handle string participant IDs
                        contact_name = self._get_contact_name_by_id(participant)
                        if contact_name:
                            enriched_list.append("{} ({})".format(participant, contact_name))
                        else:
                            enriched_list.append(participant)
                    else:
                        enriched_list.append(participant)
                return enriched_list
                
            # Handle dict format (single participant or complex structure)
            elif isinstance(participants_data, dict):
                enriched_dict = dict(participants_data)  # Create a copy
                for key, value in participants_data.items():
                    # Look for ID-like fields
                    if any(id_key in key.lower() for id_key in ["id", "participant", "user", "mri"]):
                        contact_name = self._get_contact_name_by_id(value)
                        if contact_name:
                            enriched_dict[key + "_enriched_name"] = contact_name
                return enriched_dict
                
        except Exception:
            # If enrichment fails, return original data
            pass
            
        return participants_data

    # Additional utility methods for thread processing
    
    def _extract_thread_data(self, thread_val):
        """Extract thread-specific data from thread value object."""
        thread_data = {}
        
        # Extract topic and description
        thread_props = thread_val.get("threadProperties", {})
        properties = thread_val.get("properties", {})
        
        # Extract topic
        if isinstance(thread_props, dict):
            topic = thread_props.get("topic")
            if not topic:
                topic = thread_props.get("title")
            if topic:
                thread_data["topic"] = topic
            
            # Extract description
            description = thread_props.get("description")
            if description:
                thread_data["description"] = description
            
            # Extract creator and creation time
            creator = thread_props.get("creator")
            if creator:
                thread_data["creator"] = creator
            
            created_at = thread_props.get("createdAt")
            if created_at:
                thread_data["created_at"] = created_at
        
        # Extract draft status
        if isinstance(properties, dict):
            has_draft = properties.get("hasMessageDraft")
            if has_draft is not None:
                thread_data["has_draft"] = "True" if has_draft else "False"
        
        # Extract member count
        roster_summary = thread_val.get("rosterSummary", {})
        if isinstance(roster_summary, dict):
            member_count = roster_summary.get("memberCount")
            if member_count is not None:
                thread_data["member_count"] = member_count
        
        return thread_data

    def _get_contact_name_by_id(self, user_id):
        """Get contact display name by user ID from contacts map."""
        if not user_id or not self.contacts_map:
            return None
        
        contact = self.contacts_map.get(user_id)
        if contact and isinstance(contact, dict):
            return contact.get("displayName") or contact.get("name")
        
        return None

    def _extract_call_recording_attributes(self, call_activity):
        """Extract recording-specific attributes from call activity."""
        attributes = {}
        
        content = call_activity.get("content", "")
        if isinstance(content, basestring):
            # Extract recording filename
            recording_match = re.search(r'<recording[^>]*?filename="([^"]*)"', content)
            if recording_match:
                attributes["recording_filename"] = recording_match.group(1)
            
            # Extract recording duration
            duration_match = re.search(r'<recording[^>]*?duration="([^"]*)"', content)
            if duration_match:
                attributes["recording_duration"] = duration_match.group(1)
            
            # Extract transcript filename
            transcript_match = re.search(r'<transcript[^>]*?filename="([^"]*)"', content)
            if transcript_match:
                attributes["transcript_filename"] = transcript_match.group(1)
        
        return attributes

    def _extract_meeting_attributes(self, message):
        """Extract meeting-specific attributes from Event/Call message."""
        attributes = {}
        
        # Extract thread topic as meeting title
        thread_topic = message.get("threadTopic", "")
        if thread_topic:
            attributes["meeting_title"] = thread_topic
        
        # Extract meeting ID from content
        content = message.get("content", "")
        if isinstance(content, basestring):
            # Look for meeting ID patterns
            meeting_id_match = re.search(r'meetingId["\s]*[:=]\s*["\']([^"\']*)', content)
            if not meeting_id_match:
                meeting_id_match = re.search(r'conference[iI]d["\s]*[:=]\s*["\']([^"\']*)', content)
            
            if meeting_id_match:
                attributes["meeting_id"] = meeting_id_match.group(1)
        
        # Extract organizer from properties
        properties = message.get("properties", {})
        if isinstance(properties, dict):
            organizer = properties.get("organizer") or properties.get("creator")
            if organizer:
                attributes["organizer"] = self._format_participant_info(organizer)
        
        return attributes

    def _add_call_log_attributes(self, artifact, call_log):
        """Add call log specific attributes to artifact."""
        try:
            # Add call duration
            start_time = call_log.get("start_time")
            end_time = call_log.get("end_time")
            if start_time and end_time:
                duration = self._calculate_call_duration(start_time, end_time)
                if duration:
                    artifact.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_END.getTypeID(), 
                                                            self.module_name, duration))
            
            # Add call type
            call_type = call_log.get("call_type", "Unknown")
            artifact.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DESCRIPTION.getTypeID(), 
                                                    self.module_name, call_type))
            
            # Add participants
            participants = call_log.get("participants", "")
            if participants:
                artifact.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_USER_NAME.getTypeID(), 
                                                        self.module_name, participants))
        
        except Exception as e:
            self._log_error("Error adding call log attributes: {}".format(str(e)))
    
    def _determine_thread_artifact_type(self, threadId):
        """Determine the appropriate artifact type based on thread ID."""
        if threadId.endswith("@thread.v2"):
            return self.art_group_chat
        elif threadId.endswith("@unq.gbl.spaces"):
            return self.art_private_chat
        elif threadId.endswith("@thread.tacv2"):
            return self.art_teams_chat
        else:
            return self.art_thread
    
    def _populate_thread_artifact(self, art, threadId, threadType, teamId, tenantId, thread_data):
        """Populate thread artifact with attributes."""
        art.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_THREAD_ID"], ARTIFACT_PREFIX, threadId))
        art.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_THREAD_TYPE"], ARTIFACT_PREFIX, threadType))
        art.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_TENANTID"], ARTIFACT_PREFIX, tenantId if tenantId else ""))
        if threadId.endswith("@thread.tacv2") and teamId:
            art.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_TEAMID"], ARTIFACT_PREFIX, teamId))
    
    def _populate_contact_artifact(self, art, contact_data):
        """Populate contact artifact with attributes."""
        # Implementation would add all contact attributes
        pass
    
    def _process_call_log(self, msg, conversation_id, jsonFile, bb):
        """
        Process call log message from 48:calllogs conversation.
        
        Args:
            msg: Message data dictionary
            conversation_id: ID of the conversation (should be "48:calllogs")
            jsonFile: File object from Autopsy
            bb: Blackboard instance
            
        Returns:
            int: Number of call logs processed (0 or 1)
        """
        msg_type = msg.get("messageType", "")
        properties = msg.get("properties", {})
        
        # Only process Text messages with call-log property
        if msg_type != "Text" or not isinstance(properties, dict) or "call-log" not in properties:
            return 0
        
        # Extract call log data
        try:
            calllog_data = json.loads(properties["call-log"]) if isinstance(properties["call-log"], basestring) else properties["call-log"]
        except Exception:
            calllog_data = {}
        
        # Extract basic message data
        seq_id = msg.get("sequenceId")
        content = msg.get("content", "")
        msg_id = msg.get("id")
        orig_arrival = msg.get("originalArrivalTime")
        
        # Convert to safe unicode strings
        content = self._safe_unicode(content)
        msg_id = self._safe_unicode(msg_id)
        
        # Extract call log specific fields
        start_time = calllog_data.get("startTime")
        end_time = calllog_data.get("endTime")
        call_direction = calllog_data.get("callDirection")
        call_type = calllog_data.get("callType")
        call_state = calllog_data.get("callState")
        call_id_val = calllog_data.get("callId")
        originator_part = calllog_data.get("originatorParticipant", {})
        target_part = calllog_data.get("targetParticipant", {})
        participants = calllog_data.get("participants")
        participant_list = calllog_data.get("participantList")
        
        # Get tenant ID for this conversation
        tenant_id = self.conversation_tenant_map.get(conversation_id, "")
        
        # Convert timestamps
        orig_arrival_ts = self._convert_timestamp(orig_arrival, for_datetime_attr=True)
        
        # Serialize properties
        properties_json = self._serialize_properties(properties)
        
        # Create call log artifact
        art = jsonFile.newArtifact(self.art_calllog_conv.getTypeID())
        
        # Add basic attributes
        art.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_TENANTID"], ARTIFACT_PREFIX, tenant_id))
        art.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_CONV_ID"], ARTIFACT_PREFIX, conversation_id))
        art.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_SEQ_ID"], ARTIFACT_PREFIX, str(seq_id)))
        art.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_CONTENT"], ARTIFACT_PREFIX, content))
        art.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_MSG_ID"], ARTIFACT_PREFIX, msg_id))
        art.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_MSG_TYPE"], ARTIFACT_PREFIX, msg_type))
        art.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_PROPERTIES"], ARTIFACT_PREFIX, properties_json))
        
        if orig_arrival_ts:
            art.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_ORIG_ARRIVAL"], ARTIFACT_PREFIX, orig_arrival_ts))
        
        # Add call-specific attributes
        self._add_call_log_attributes(art, calllog_data, bb)
        
        bb.indexArtifact(art)
        return 1

    def _add_call_log_attributes(self, art, calllog_data, bb):
        """Add call log specific attributes to artifact."""
        # Create additional call log attributes if they don't exist
        if not hasattr(self, 'attr_calllog_extras'):
            self.attr_calllog_extras = {}
            for name, vtype, desc in [
                ("TSK_TEAMS_CALLLOG_STARTTIME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Start Time"),
                ("TSK_TEAMS_CALLLOG_ENDTIME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "End Time"),
                ("TSK_TEAMS_CALLLOG_DURATION_CALC", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Call Duration (hh:mm:ss)"),
                ("TSK_TEAMS_CALLLOG_DIRECTION", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Call Direction"),
                ("TSK_TEAMS_CALLLOG_CALLTYPE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Call Type"),
                ("TSK_TEAMS_CALLLOG_STATE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "State"),
                ("TSK_TEAMS_CALLLOG_CALLID2", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Call ID"),
                ("TSK_TEAMS_CALLLOG_ORIGINATOR", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Originator"),
                ("TSK_TEAMS_CALLLOG_TARGET", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Target Participant"),
                ("TSK_TEAMS_CALLLOG_PARTICIPANTS", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Participants List"),
                ("TSK_TEAMS_CALLLOG_PARTICIPANT_LIST", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Participants List (json)")
            ]:
                self.attr_calllog_extras[name] = bb.getOrAddAttributeType(name, vtype, desc)
        
        # Add attributes with values
        start_time = calllog_data.get("startTime")
        end_time = calllog_data.get("endTime")
        
        if start_time:
            art.addAttribute(BlackboardAttribute(self.attr_calllog_extras["TSK_TEAMS_CALLLOG_STARTTIME"], 
                                               ARTIFACT_PREFIX, self._convert_timestamp(start_time, for_datetime_attr=False)))
        if end_time:
            art.addAttribute(BlackboardAttribute(self.attr_calllog_extras["TSK_TEAMS_CALLLOG_ENDTIME"], 
                                               ARTIFACT_PREFIX, self._convert_timestamp(end_time, for_datetime_attr=False)))
        
        # Calculate and add duration
        if start_time and end_time:
            duration = self._calculate_call_duration(start_time, end_time)
            if duration:
                art.addAttribute(BlackboardAttribute(self.attr_calllog_extras["TSK_TEAMS_CALLLOG_DURATION_CALC"], 
                                                   ARTIFACT_PREFIX, duration))
        
        # Add other call log fields
        if calllog_data.get("callDirection"):
            art.addAttribute(BlackboardAttribute(self.attr_calllog_extras["TSK_TEAMS_CALLLOG_DIRECTION"], 
                                               ARTIFACT_PREFIX, str(calllog_data["callDirection"])))
        if calllog_data.get("callType"):
            art.addAttribute(BlackboardAttribute(self.attr_calllog_extras["TSK_TEAMS_CALLLOG_CALLTYPE"], 
                                               ARTIFACT_PREFIX, str(calllog_data["callType"])))
        if calllog_data.get("callState"):
            art.addAttribute(BlackboardAttribute(self.attr_calllog_extras["TSK_TEAMS_CALLLOG_STATE"], 
                                               ARTIFACT_PREFIX, str(calllog_data["callState"])))
        if calllog_data.get("callId"):
            art.addAttribute(BlackboardAttribute(self.attr_calllog_extras["TSK_TEAMS_CALLLOG_CALLID2"], 
                                               ARTIFACT_PREFIX, str(calllog_data["callId"])))
        
        # Add participant information
        originator_part = calllog_data.get("originatorParticipant", {})
        target_part = calllog_data.get("targetParticipant", {})
        
        if originator_part:
            originator_str = self._format_participant_info(originator_part)
            art.addAttribute(BlackboardAttribute(self.attr_calllog_extras["TSK_TEAMS_CALLLOG_ORIGINATOR"], 
                                               ARTIFACT_PREFIX, originator_str))
        
        if target_part:
            target_str = self._format_participant_info(target_part)
            art.addAttribute(BlackboardAttribute(self.attr_calllog_extras["TSK_TEAMS_CALLLOG_TARGET"], 
                                               ARTIFACT_PREFIX, target_str))
        
        # Add participant lists
        participants = calllog_data.get("participants")
        participant_list = calllog_data.get("participantList")
        
        if participants:
            participants_str = self._format_participants_list(participants)
            art.addAttribute(BlackboardAttribute(self.attr_calllog_extras["TSK_TEAMS_CALLLOG_PARTICIPANTS"], 
                                               ARTIFACT_PREFIX, participants_str))
        
        if participant_list:
            try:
                participant_list_json = json.dumps(participant_list, ensure_ascii=False, separators=(',', ':'))
                art.addAttribute(BlackboardAttribute(self.attr_calllog_extras["TSK_TEAMS_CALLLOG_PARTICIPANT_LIST"], 
                                                   ARTIFACT_PREFIX, participant_list_json))
            except Exception:
                pass
    
    def _process_call_activity(self, msg, conversation_id, jsonFile, bb):
        """
        Process call activity message (recordings, transcripts).
        
        Args:
            msg: Message data dictionary
            conversation_id: ID of the conversation
            jsonFile: File object from Autopsy
            bb: Blackboard instance
            
        Returns:
            int: Number of call activities processed (0 or 1)
        """
        # Extract message data
        seq_id = msg.get("sequenceId")
        content = msg.get("content", "")
        msg_id = msg.get("id")
        msg_type = msg.get("messageType")
        orig_arrival = msg.get("originalArrivalTime")
        properties = msg.get("properties", {})
        
        # Convert to safe unicode strings
        content = self._safe_unicode(content)
        msg_id = self._safe_unicode(msg_id)
        msg_type = self._safe_unicode(msg_type)
        
        # Get tenant ID for this conversation
        tenant_id = self.conversation_tenant_map.get(conversation_id, "")
        
        # Convert timestamps
        orig_arrival_ts = self._convert_timestamp(orig_arrival, for_datetime_attr=True)
        edit_time_val = self._extract_timestamp_from_properties(properties, "edittime")
        compose_time_val = self._extract_timestamp_from_properties(properties, "composetime")
        delete_time_val = self._extract_timestamp_from_properties(properties, "deletetime")
        
        # Serialize properties
        properties_json = self._serialize_properties(properties)
        
        # Create call activity artifact
        art = jsonFile.newArtifact(self.art_calllog_msg.getTypeID())
        
        # Add basic attributes
        art.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_TENANTID"], ARTIFACT_PREFIX, tenant_id))
        art.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_CONV_ID"], ARTIFACT_PREFIX, conversation_id))
        art.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_SEQ_ID"], ARTIFACT_PREFIX, str(seq_id)))
        art.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_CONTENT"], ARTIFACT_PREFIX, content))
        art.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_MSG_ID"], ARTIFACT_PREFIX, msg_id))
        art.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_MSG_TYPE"], ARTIFACT_PREFIX, msg_type))
        art.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_PROPERTIES"], ARTIFACT_PREFIX, properties_json))
        
        # Add timestamps
        if orig_arrival_ts:
            art.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_ORIG_ARRIVAL"], ARTIFACT_PREFIX, orig_arrival_ts))
        if edit_time_val:
            art.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_EDIT_TIME"], ARTIFACT_PREFIX, edit_time_val))
        if compose_time_val:
            art.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_COMPOSE_TIME"], ARTIFACT_PREFIX, compose_time_val))
        if delete_time_val:
            art.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_DELETE_TIME"], ARTIFACT_PREFIX, delete_time_val))
        
        # Extract special attributes for call recordings
        if msg_type == "RichText/Media_CallRecording":
            self._extract_call_recording_attributes(art, content)
        
        bb.indexArtifact(art)
        return 1

    def _extract_call_recording_attributes(self, art, content):
        """Extract specific attributes from call recording content."""
        # Recording status
        match = re.search(r'<RecordingStatus[^>]*status="([^"]+)"', content)
        if match:
            art.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_CALLLOG_STATUS"], ARTIFACT_PREFIX, match.group(1)))
        
        # Original name
        match = re.search(r'<OriginalName[^>]*v="([^"]+)"', content)
        if match:
            art.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_CALLLOG_ORIGINALNAME"], ARTIFACT_PREFIX, match.group(1)))
        
        # Recording initiator
        match = re.search(r'<RecordingInitiatorId[^>]*value="([^"]+)"', content)
        if match:
            initiator_id = match.group(1)
            enriched_initiator_id = self._enrich_creator_with_name(initiator_id)
            art.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_CALLLOG_INITIATOR"], ARTIFACT_PREFIX, enriched_initiator_id))
        
        # Recording terminator
        match = re.search(r'<RecordingTerminatorId[^>]*value="([^"]+)"', content)
        if match:
            terminator_id = match.group(1)
            enriched_terminator_id = self._enrich_creator_with_name(terminator_id)
            art.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_CALLLOG_TERMINATOR"], ARTIFACT_PREFIX, enriched_terminator_id))
        
        # Call ID
        match = re.search(r'<Id[^>]*type="callId"[^>]*value="([^"]+)"', content)
        if match:
            art.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_CALLLOG_CALLID"], ARTIFACT_PREFIX, match.group(1)))
        
        # Duration
        match = re.search(r'<RecordingContent[^>]*duration="([^"]+)"', content)
        if match:
            art.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_CALLLOG_DURATION"], ARTIFACT_PREFIX, match.group(1)))
        
        # Timestamp
        match = re.search(r'<RecordingContent[^>]*timestamp="([^"]+)"', content)
        if match:
            timestamp_raw = match.group(1)
            timestamp_formatted = self._convert_timestamp(timestamp_raw, for_datetime_attr=False)
            art.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_CALLLOG_TIMESTAMP"], ARTIFACT_PREFIX, timestamp_formatted))
        
        # Meeting organizer
        match = re.search(r'<MeetingOrganizerId[^>]*value="([^"]*)"', content)
        if match:
            organizer_id = match.group(1)
            enriched_organizer_id = self._enrich_creator_with_name(organizer_id) if organizer_id else ""
            art.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_CALLLOG_MEETING_ORGID"], ARTIFACT_PREFIX, enriched_organizer_id))
    
    def _process_meeting_event(self, msg, conversation_id, jsonFile, bb):
        """
        Process meeting event message (Event/Call type).
        
        Args:
            msg: Message data dictionary
            conversation_id: ID of the conversation
            jsonFile: File object from Autopsy
            bb: Blackboard instance
            
        Returns:
            int: Number of meeting events processed (0 or 1)
        """
        # Extract message data
        seq_id = msg.get("sequenceId")
        content = msg.get("content", "")
        msg_id = msg.get("id")
        creator = msg.get("creator")
        msg_type = msg.get("messageType")
        orig_arrival = msg.get("originalArrivalTime")
        properties = msg.get("properties", {})
        
        # Convert to safe unicode strings
        content = self._safe_unicode(content)
        msg_id = self._safe_unicode(msg_id)
        creator = self._safe_unicode(creator)
        msg_type = self._safe_unicode(msg_type)
        
        # Get tenant ID for this conversation
        tenant_id = self.conversation_tenant_map.get(conversation_id, "")
        
        # Convert timestamps
        orig_arrival_ts = self._convert_timestamp(orig_arrival, for_datetime_attr=True)
        edit_time_val = self._extract_timestamp_from_properties(properties, "edittime")
        compose_time_val = self._extract_timestamp_from_properties(properties, "composetime")
        delete_time_val = self._extract_timestamp_from_properties(properties, "deletetime")
        
        # Serialize properties
        properties_json = self._serialize_properties(properties)
        
        # Enrich creator with contact name
        enriched_creator = self._enrich_creator_with_name(creator)
        
        # Create meeting event artifact
        art = jsonFile.newArtifact(self.art_eventcall.getTypeID())
        
        # Add basic attributes
        art.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_TENANTID"], ARTIFACT_PREFIX, tenant_id))
        art.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_CONV_ID"], ARTIFACT_PREFIX, conversation_id))
        art.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_SEQ_ID"], ARTIFACT_PREFIX, str(seq_id)))
        art.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_CONTENT"], ARTIFACT_PREFIX, content))
        art.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_MSG_ID"], ARTIFACT_PREFIX, msg_id))
        art.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_CREATOR"], ARTIFACT_PREFIX, enriched_creator))
        art.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_MSG_TYPE"], ARTIFACT_PREFIX, msg_type))
        art.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_PROPERTIES"], ARTIFACT_PREFIX, properties_json))
        
        # Add timestamps
        if orig_arrival_ts:
            art.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_ORIG_ARRIVAL"], ARTIFACT_PREFIX, orig_arrival_ts))
        if edit_time_val:
            art.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_EDIT_TIME"], ARTIFACT_PREFIX, edit_time_val))
        if compose_time_val:
            art.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_COMPOSE_TIME"], ARTIFACT_PREFIX, compose_time_val))
        if delete_time_val:
            art.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_DELETE_TIME"], ARTIFACT_PREFIX, delete_time_val))
        
        # Extract meeting-specific attributes
        self._extract_meeting_attributes(art, properties, bb)
        
        bb.indexArtifact(art)
        return 1

    def _extract_meeting_attributes(self, art, properties, bb):
        """Extract meeting-specific attributes from properties."""
        # Create additional meeting attributes if they don't exist
        if not hasattr(self, 'attr_eventcall_extras'):
            self.attr_eventcall_extras = {}
            for name, vtype, desc in [
                ("TSK_TEAMS_EVENTCALL_PARTICIPANTS", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Meeting Participants"),
                ("TSK_TEAMS_EVENTCALL_ORGANIZERUPN", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Meeting Organizer Email"),
                ("TSK_TEAMS_EVENTCALL_MEETINGTYPE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Meeting Type"),
                ("TSK_TEAMS_EVENTCALL_STARTTIME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Meeting Start Time"),
                ("TSK_TEAMS_EVENTCALL_ENDTIME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Meeting End Time")
            ]:
                self.attr_eventcall_extras[name] = bb.getOrAddAttributeType(name, vtype, desc)
        
        if not isinstance(properties, dict):
            return
        
        # Extract participants information
        participants = properties.get("participants")
        if participants:
            participants_enriched = self._enrich_participants_with_names(participants)
            try:
                participants_str = json.dumps(participants_enriched, ensure_ascii=False, separators=(',', ':'))
                art.addAttribute(BlackboardAttribute(self.attr_eventcall_extras["TSK_TEAMS_EVENTCALL_PARTICIPANTS"], 
                                                   ARTIFACT_PREFIX, participants_str))
            except Exception:
                pass
        
        # Extract organizer information
        organizer_upn = properties.get("organizerUpn")
        if organizer_upn:
            art.addAttribute(BlackboardAttribute(self.attr_eventcall_extras["TSK_TEAMS_EVENTCALL_ORGANIZERUPN"], 
                                               ARTIFACT_PREFIX, str(organizer_upn)))
        
        # Extract meeting type
        meeting_type = properties.get("meetingType")
        if meeting_type:
            art.addAttribute(BlackboardAttribute(self.attr_eventcall_extras["TSK_TEAMS_EVENTCALL_MEETINGTYPE"], 
                                               ARTIFACT_PREFIX, str(meeting_type)))
        
        # Extract meeting times
        start_time = properties.get("startTime")
        if start_time:
            start_time_formatted = self._convert_timestamp(start_time, for_datetime_attr=False)
            art.addAttribute(BlackboardAttribute(self.attr_eventcall_extras["TSK_TEAMS_EVENTCALL_STARTTIME"], 
                                               ARTIFACT_PREFIX, start_time_formatted))
        
        end_time = properties.get("endTime")
        if end_time:
            end_time_formatted = self._convert_timestamp(end_time, for_datetime_attr=False)
            art.addAttribute(BlackboardAttribute(self.attr_eventcall_extras["TSK_TEAMS_EVENTCALL_ENDTIME"], 
                                               ARTIFACT_PREFIX, end_time_formatted))
    
    def _process_message_reactions(self, msg, conversation_id, jsonFile, bb):
        """
        Process message reactions (emotions/likes).
        
        Args:
            msg: Message data dictionary
            conversation_id: ID of the conversation
            jsonFile: File object from Autopsy
            bb: Blackboard instance
        """
        properties = msg.get("properties", {})
        if not isinstance(properties, dict):
            return
        
        msg_id = self._safe_unicode(msg.get("id"))
        seq_id = msg.get("sequenceId")
        tenant_id = self.conversation_tenant_map.get(conversation_id, "")
        
        # Process emotions/reactions
        for react_key in ["emotions"]:
            react_obj = properties.get(react_key)
            if react_obj and isinstance(react_obj, dict):
                values = react_obj.get("values", [])
                for v in values:
                    reaction_type = v.get("key")
                    users_obj = v.get("users", {})
                    users = users_obj.get("values", []) if isinstance(users_obj, dict) else []
                    
                    for u in users:
                        mri = u.get("mri", "")
                        time_val = u.get("time", None)
                        time_val = self._convert_timestamp(time_val, for_datetime_attr=True)
                        
                        # Enrich MRI with contact name in parentheses
                        enriched_mri = self._enrich_creator_with_name(mri) if mri else mri
                        
                        # Create reaction artifact
                        art_react = jsonFile.newArtifact(self.art_reaction.getTypeID())
                        art_react.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_TENANTID"], ARTIFACT_PREFIX, tenant_id))
                        art_react.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_REACTION_MSG_ID"], ARTIFACT_PREFIX, msg_id))
                        art_react.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_REACTION_SEQ_ID"], ARTIFACT_PREFIX, str(seq_id)))
                        art_react.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_REACTION_TYPE"], ARTIFACT_PREFIX, reaction_type if reaction_type else ""))
                        art_react.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_REACTION_MRI"], ARTIFACT_PREFIX, enriched_mri))
                        
                        if time_val:
                            art_react.addAttribute(BlackboardAttribute(self.attr["TSK_TEAMS_REACTION_TIME"], ARTIFACT_PREFIX, time_val))
                        

                        bb.indexArtifact(art_react)
