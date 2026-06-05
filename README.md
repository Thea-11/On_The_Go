# On The Go

On The Go is an AI travel operations agent that helps groups plan, organize, collaborate, and split trip costs in one place.

It goes beyond a simple chatbot: the agent creates structured travel plans, turns them into editable daily itineraries, enriches activities with real Google Places data, stores trip memory in MongoDB, supports collaborators, creates shareable read-only trip pages, and calculates multi-currency group settlements.

## Problem

Group travel planning is messy. Travelers often need to manage flights, daily routes, real place recommendations, shared notes, collaborators, expenses, currency conversion, and final settlement across many separate apps.

On The Go brings these workflows together into one AI-powered travel agent.

## Solution

On The Go allows users to:

* Generate a trip from a confirmed flight or estimated travel dates
* Create daily itineraries with times, locations, transportation, and travel time
* Enrich recommended places with real Google Places data such as ratings, reviews, addresses, price level, websites, and Google Maps links
* Edit itinerary items manually
* Save trips, templates, projects, and expenses in MongoDB
* Invite collaborators as editors or viewers
* Create public read-only share links
* Track multi-currency expenses
* Calculate who owes whom in a selected settlement currency
* Print flight information and final itineraries as PDF-ready pages

## Agent Workflow

The agent performs a multi-step workflow:

1. Understands the user's travel context, such as flight number, flight date, destination, trip length, hotel area, budget, food preferences, travel pace, and must-see places.
2. Uses Gemini to reason over the request and produce a structured JSON travel plan.
3. Converts the plan into editable itinerary records.
4. Uses Google Places API to enrich recommended activities with real-world place data.
5. Stores trips, itinerary items, expenses, templates, projects, users, and collaborators in MongoDB.
6. Converts expenses across currencies and calculates final settlements.
7. Lets users revise, share, print, and reuse the final plan.

## Key Features

### AI Trip Generation

Users can create trips in two modes:

* Confirmed flight mode: for users who already have a flight number and flight date
* Estimated trip mode: for users who have not bought tickets yet but know the destination, start date, and trip length

The agent creates a flexible itinerary based on the user's travel situation.

### Real Place Enrichment

The app uses Google Places API to enrich itinerary activities with real-world data, including:

* Place name
* Address
* Rating
* Review count
* Price level
* Website link
* Google Maps link

### Editable Daily Itinerary

After the agent generates a trip, the daily itinerary becomes editable. Users can add, update, or delete activities. Each activity can include time, location, transportation, travel time, notes, and recommended place information.

### Collaboration

Trip owners can invite collaborators by email. Collaborators can be assigned as:

* Editor
* Viewer

The app also supports public read-only share links.

### Expenses and Settlement

Users can track group expenses in multiple currencies. The app converts expenses into a selected settlement currency and calculates who owes whom.

### Templates and Projects

Users can save trips as templates and organize trips into projects.

### PDF-ready Print Pages

The app includes print pages for:

* Flight information
* Final itinerary

Users can save these pages as PDFs from the browser.

## Built With

* Node.js
* Express.js
* MongoDB Atlas
* MongoDB Node.js Driver
* Gemini API
* Google Places API
* Google Cloud Run
* Docker
* Frankfurter Exchange Rate API
* HTML
* CSS
* JavaScript
* JWT authentication
* bcryptjs

## Google Cloud and Partner Track

This project is submitted for the MongoDB partner track.

Google Cloud is used to host and run the application through Cloud Run. Gemini powers the reasoning layer for itinerary generation and agent planning. MongoDB provides the persistent memory layer for trips, itinerary items, expenses, templates, projects, users, and collaboration data.

## Project Structure

```text
travel_agent/
├── public/
│   └── index.html
├── server.js
├── package.json
├── package-lock.json
├── Dockerfile
├── .env.example
├── .gitignore
├── .gcloudignore
├── README.md
└── LICENSE
```

## Environment Variables

Create a `.env` file based on `.env.example`:

```env
PORT=3000

MONGODB_URI=your_mongodb_atlas_connection_string
DB_NAME=travel_db

GEMINI_API_KEY=your_gemini_api_key
GOOGLE_PLACES_API_KEY=your_google_places_api_key

JWT_SECRET=change_this_to_a_long_random_secret
```

## Run Locally

Install dependencies:

```bash
npm install
```

Start the server:

```bash
npm start
```

Open the app in your browser:

```text
http://localhost:3000
```

## Deployment

The app can be deployed to Google Cloud Run using the included Dockerfile.

Example deployment flow:

```bash
gcloud run deploy on-the-go \
  --source . \
  --region us-central1 \
  --allow-unauthenticated
```

Environment variables should be configured securely in Google Cloud Run.

## Demo Flow

A typical demo shows:

1. Register or log in
2. Generate a trip from a flight number or estimated dates
3. View the generated itinerary
4. Check real Google Places ratings and map links
5. Edit itinerary activities
6. Invite a collaborator or create a share link
7. Add multi-currency expenses
8. Calculate the final settlement
9. Print the final itinerary

## License

This project is licensed under the MIT License.
