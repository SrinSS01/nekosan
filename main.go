package nekosan

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/GoogleCloudPlatform/functions-framework-go/functions"
	"io"
	"net/http"
	"os"
)

// --- Configuration ---
// Discord Application Public Key (set via environment variable DISCORD_PUBLIC_KEY)
var discordPublicKey ed25519.PublicKey

// --- Constants for Discord Interaction Types ---
// https://discord.com/developers/docs/interactions/receiving-and-responding#interaction-object-interaction-type
const (
	InteractionTypePing               = 1
	InteractionTypeApplicationCommand = 2
	InteractionTypeMessageComponent   = 3
	InteractionTypeAutocomplete       = 4
	InteractionTypeModalSubmit        = 5
)

// --- Constants for Discord Interaction Response Types ---
// https://discord.com/developers/docs/interactions/receiving-and-responding#interaction-response-object-interaction-response-type
const (
	InteractionResponseTypePong                             = 1
	InteractionResponseTypeChannelMessageWithSource         = 4
	InteractionResponseTypeDeferredChannelMessageWithSource = 5
	InteractionResponseTypeDeferredUpdateMessage            = 6
	InteractionResponseTypeUpdateMessage                    = 7
	InteractionResponseTypeAutocompleteResult               = 8
	InteractionResponseTypeModal                            = 9
	InteractionResponseTypePremiumRequired                  = 10
)

// --- Constants for Discord Message Flags ---
const (
	MessageFlagCrossposted                  = 1 << 0  // Message has been published to subscribed channels
	MessageFlagIsCrosspost                  = 1 << 1  // Message originated from another channel
	MessageFlagSuppressEmbeds               = 1 << 2  // Do not include embeds when serializing
	MessageFlagSourceMessageDeleted         = 1 << 3  // Source message for crosspost has been deleted
	MessageFlagUrgent                       = 1 << 4  // Message from urgent message system
	MessageFlagHasThread                    = 1 << 5  // Message has associated thread
	MessageFlagEphemeral                    = 1 << 6  // Message only visible to interaction invoker
	MessageFlagLoading                      = 1 << 7  // Message is an interaction response thinking state
	MessageFlagFailedToMentionRolesInThread = 1 << 8  // Failed to mention roles in thread
	MessageFlagSuppressNotifications        = 1 << 12 // No push/desktop notifications
	MessageFlagIsVoiceMessage               = 1 << 13 // Message is a voice message
	MessageFlagHasSnapshot                  = 1 << 14 // Message has snapshot
	MessageFlagIsComponentsV2               = 1 << 15 // Message uses components V2
)

// DiscordInteraction Struct to represent the incoming Discord Interaction payload
// Only includes fields needed for basic handling
type DiscordInteraction struct {
	Type  int             `json:"type"` // The type of interaction
	Data  json.RawMessage `json:"data"` // The command data (use RawMessage to parse later)
	ID    string          `json:"id"`
	Token string          `json:"token"`
	// ... other fields you might need later (guild_id, channel_id, member, user, app_permissions etc.)
}

// DiscordInteractionResponse Structs for potential Responses (basic examples)
type DiscordInteractionResponse struct {
	Type int                             `json:"type"`           // The type of response
	Data *DiscordInteractionResponseData `json:"data,omitempty"` // Data for the response (optional)
}

type DiscordInteractionResponseData struct {
	Content         string        `json:"content,omitempty"`          // Message content
	Flags           int           `json:"flags,omitempty"`            // Message flags (e.g., 64 for EPHEMERAL)
	TTS             bool          `json:"tts,omitempty"`              // Text-to-speech
	Embeds          []interface{} `json:"embeds,omitempty"`           // Embeds (use proper structs later)
	AllowedMentions interface{}   `json:"allowed_mentions,omitempty"` // Allowed mentions
	Components      []interface{} `json:"components,omitempty"`       // Message components (buttons, select menus)
	Choices         []interface{} `json:"choices,omitempty"`          // Autocomplete choices
	CustomID        string        `json:"custom_id,omitempty"`        // Modal custom ID
	Title           string        `json:"title,omitempty"`            // Modal title
}

// init is called when the function is initialized. Use it for setup.
func init() {
	// Register the HTTP function handler
	functions.HTTP("DiscordInteractionsHandler", DiscordInteractionsHandler)

	// Load the public key from environment variable
	publicKeyHex := os.Getenv("DISCORD_PUBLIC_KEY")
	if publicKeyHex == "" {
		// This will cause the function initialization to fail if the key is missing,
		// which is good because the function won't work without it.
		panic("FATAL ERROR: DISCORD_PUBLIC_KEY environment variable not set. Go to Discord Developer Portal -> Applications -> Your App -> General Information, copy the 'Public Key', and set it during deployment.")
	}

	var err error
	discordPublicKey, err = hex.DecodeString(publicKeyHex)
	if err != nil {
		// Invalid hex key format
		panic(fmt.Sprintf("FATAL ERROR: Invalid Discord Public Key format. Expected hex string: %v", err))
	}

	// Check if the key has the correct length for Ed25519
	if len(discordPublicKey) != ed25519.PublicKeySize {
		panic(fmt.Sprintf("FATAL ERROR: Invalid Discord Public Key length. Expected %d bytes, got %d.", ed25519.PublicKeySize, len(discordPublicKey)))
	}

	fmt.Println("Discord Public Key loaded successfully.")
}

// DiscordInteractionsHandler is the entry point for Discord Interaction HTTP requests.
func DiscordInteractionsHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Received HTTP request.")

	// Ensure it's a POST request
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		fmt.Printf("Received method %s, expected POST.\n", r.Method)
		return
	}

	// 1. Get headers
	signature := r.Header.Get("X-Signature-Ed25519")
	timestamp := r.Header.Get("X-Signature-Timestamp")

	fmt.Printf("Headers - Signature: %s, Timestamp: %s\n", signature, timestamp)

	// 2. Read the raw request body
	body, err := io.ReadAll(r.Body)
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			fmt.Printf("Error closing body: %v\n", err)
		}
	}(r.Body) // Ensure body is closed
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusInternalServerError)
		fmt.Printf("Error reading body: %v\n", err)
		return
	}
	fmt.Printf("Raw Body (first 100 chars): %s...\n", string(body[:min(len(body), 100)]))

	// 3. Verify the signature
	// Discord signature verification requires the timestamp and the raw body
	if signature == "" || timestamp == "" {
		http.Error(w, "Missing signature headers", http.StatusUnauthorized)
		fmt.Println("Missing signature headers.")
		return
	}

	// Decode the hex signature string
	signatureBytes, err := hex.DecodeString(signature)
	if err != nil {
		http.Error(w, "Invalid signature header format", http.StatusUnauthorized)
		fmt.Printf("Invalid signature hex format: %v\n", err)
		return
	}

	// The message to verify is the timestamp concatenated with the raw body
	message := append([]byte(timestamp), body...)

	// Perform the verification
	// This function returns true if the signature is valid, false otherwise
	if !ed25519.Verify(discordPublicKey, message, signatureBytes) {
		http.Error(w, "Invalid signature", http.StatusUnauthorized)
		fmt.Println("Signature verification failed.")
		return
	}

	fmt.Println("Signature verification successful.")

	// 4. Parse the request body as JSON
	var interaction DiscordInteraction
	err = json.Unmarshal(body, &interaction)
	if err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		fmt.Printf("Failed to parse JSON body: %v\n", err)
		return
	}
	fmt.Printf("Parsed Interaction Type: %d\n", interaction.Type)

	// 5. Handle the Interaction Type

	// If it's a PING, respond with a PONG
	if interaction.Type == InteractionTypePing {
		fmt.Println("Received PING, sending PONG.")
		response := DiscordInteractionResponse{Type: InteractionResponseTypePong}
		sendJSONResponse(w, response, http.StatusOK) // Use helper to send JSON
		return
	}

	// If it's any other type (like APPLICATION_COMMAND), handle accordingly
	// This is where you'd add logic for Slash Commands, Button clicks, etc.
	if interaction.Type == InteractionTypeApplicationCommand {
		// You would typically unmarshal interaction.Data here into a specific
		// command structure to get options etc. For now, just acknowledge.

		fmt.Println("Received APPLICATION_COMMAND interaction.")
		// Respond with a simple ephemeral message
		response := DiscordInteractionResponse{
			Type: InteractionResponseTypeChannelMessageWithSource,
			Data: &DiscordInteractionResponseData{
				Content: "https://api.thecatapi.com/v1/images/search?size=small&mime_types=jpg&format=src&order=RANDOM",
			},
		}
		sendJSONResponse(w, response, http.StatusOK) // Use helper to send JSON
		return
	}

	// Add handling for other types like MESSAGE_COMPONENT, MODAL_SUBMIT etc. here
	// if interaction.Type == InteractionTypeMessageComponent { ... }

	// If the type is unknown or not handled
	fmt.Printf("Received unhandled interaction type: %d\n", interaction.Type)
	// You can return a 200 OK with a minimal response type, or perhaps a 400 Bad Request
	// A 200 OK with a response is generally safer to avoid Discord retrying.
	response := DiscordInteractionResponse{
		Type: InteractionResponseTypeChannelMessageWithSource,
		Data: &DiscordInteractionResponseData{
			Content: fmt.Sprintf("Received unhandled interaction type: %d", interaction.Type),
			Flags:   64, // EPHEMERAL
		},
	}
	sendJSONResponse(w, response, http.StatusOK)
	return // Important to return after handling
}

// Helper function to send JSON responses
func sendJSONResponse(w http.ResponseWriter, data interface{}, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		fmt.Printf("Error encoding JSON response: %v\n", err)
		// If sending the response fails, we can't really recover gracefully here.
		// Log the error and the function will likely terminate.
	}
}
