# Web Scraper Application

A full-stack web scraper application built with **React.js** frontend and **Python Flask** backend.

## Features

- Scrape any website by entering its URL
- Extract comprehensive data including:
  - Page title and meta tags
  - Headings (H1-H6)
  - Paragraphs
  - Links
  - Images with alt text
  - Tables
  - Lists (ordered and unordered)
  - Full text content
- Export scraped data as:
  - **CSV** format
  - **DOCX** (Microsoft Word) format
- Modern, responsive dark-themed UI
- Real-time loading indicators
- Toast notifications for user feedback

## Project Structure

```
web_scrapper/
├── backend/              # Python Flask backend
│   ├── app.py           # Main Flask application
│   └── requirements.txt  # Python dependencies
├── frontend/            # React.js frontend
│   ├── public/
│   ├── src/
│   │   ├── App.js       # Main React component
│   │   ├── App.css      # Styles
│   │   ├── index.js     # Entry point
│   │   └── index.css    # Global styles
│   └── package.json     # Node dependencies
└── README.md
```

## Prerequisites

- Python 3.8 or higher
- Node.js 16 or higher
- npm or yarn

## Installation & Setup

### 1. Backend Setup

```bash
# Navigate to backend directory
cd backend

# Create virtual environment (recommended)
python -m venv venv

# Activate virtual environment
# On macOS/Linux:
source venv/bin/activate
# On Windows:
# venv\Scripts\activate

# Install Python dependencies
pip install -r requirements.txt
```

### 2. Frontend Setup

```bash
# Navigate to frontend directory (in a new terminal)
cd frontend

# Install Node dependencies
npm install
```

## Running the Application

### 1. Start the Backend Server

```bash
# In the backend directory
# Make sure your virtual environment is activated
python app.py
```

The Flask server will start on `http://localhost:5000`

### 2. Start the Frontend Development Server

```bash
# In the frontend directory (new terminal)
npm start
```

The React development server will start on `http://localhost:3000`

### 3. Access the Application

Open your browser and go to: `http://localhost:3000`

## Usage

1. Enter a website URL in the input field (e.g., `https://example.com`)
2. Click the **"Scrape Website"** button
3. Wait for the scraping to complete
4. Browse through the different tabs to view extracted data:
   - Overview: Summary statistics and meta tags
   - Headings: All H1-H6 headings
   - Paragraphs: All paragraph text
   - Links: All hyperlinks with their URLs
   - Images: Image sources and alt text
   - Tables: Extracted table data
   - Lists: Ordered and unordered lists
   - Full Text: Complete page text content
5. Click **"Export as CSV"** or **"Export as DOC"** to download the data

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/scrape` | POST | Scrape a website and return data |
| `/api/export/csv/<session_id>` | GET | Export data as CSV |
| `/api/export/doc/<session_id>` | GET | Export data as DOCX |
| `/api/clear/<session_id>` | DELETE | Clear stored session data |

## Technologies Used

### Backend
- **Flask**: Web framework
- **BeautifulSoup4**: HTML parsing and scraping
- **Requests**: HTTP requests
- **pandas**: Data manipulation for CSV export
- **python-docx**: DOCX file generation
- **validators**: URL validation

### Frontend
- **React.js**: UI library
- **Axios**: HTTP client
- **react-spinners**: Loading animations
- **react-toastify**: Toast notifications

## Security Notes

- Only scrape websites you have permission to access
- Respect robots.txt and website terms of service
- The scraper uses a User-Agent header to identify itself
- Some websites may block scraping - results may vary

## Troubleshooting

### Backend Issues
- **Port 5000 is already in use**: Change the port in `app.py` (line with `app.run()`)
- **Module not found errors**: Ensure all dependencies are installed with `pip install -r requirements.txt`

### Frontend Issues
- **npm install fails**: Try deleting `node_modules` and `package-lock.json`, then run `npm install` again
- **Proxy errors**: Ensure the backend is running on port 5000

### Scraping Issues
- **Empty results**: Some websites use JavaScript frameworks that require browser rendering
- **Access denied**: The website may be blocking automated requests
- **Timeout**: Large websites may take longer to scrape

## License

MIT License - Feel free to use and modify as needed.
