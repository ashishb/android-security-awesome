import re
import os
import webbrowser
import requests

# Filepath to the README.md file
README_FILE = "README.md"

# GitHub API URL for fetching repository data
GITHUB_API_URL = "https://api.github.com/repos/"

# Function to parse tools and links from the README.md file
def parse_tools(readme_path):
    tools = []
    current_category = None

    with open(readme_path, "r") as f:
        for line in f:
            # Detect categories (e.g., "## Static Analysis Tools")
            category_match = re.match(r"^##\s+(.+)$", line)
            if category_match:
                current_category = category_match.group(1).strip()
                continue

            # Detect tool links (e.g., "1. [Tool Name](https://example.com)")
            tool_match = re.match(r"^\d+\.\s+\[(.+?)\]\((https?://.+?)\)\s*-?\s*(.*)$", line)
            if tool_match:
                tool_name = tool_match.group(1).strip()
                tool_url = tool_match.group(2).strip()
                tool_desc = tool_match.group(3).strip()

                tools.append({
                    "name": tool_name,
                    "url": tool_url,
                    "desc": tool_desc,
                    "category": current_category,
                })

    return tools

# Function to fetch GitHub metadata (stars, last updated)
def fetch_github_metadata(url):
    if "github.com" not in url:
        return None

    try:
        # Extract owner and repo name from the URL
        repo_path = re.search(r"github.com/([^/]+/[^/]+)/?", url).group(1)
        response = requests.get(GITHUB_API_URL + repo_path)

        if response.status_code == 200:
            data = response.json()
            return {
                "stars": data.get("stargazers_count", "N/A"),
                "last_updated": data.get("updated_at", "N/A"),
            }
    except Exception as e:
        print(f"Error fetching metadata for {url}: {e}")

    return None

# Function to display tools by category
def list_tools_by_category(tools):
    categories = sorted(set(tool["category"] for tool in tools if tool["category"]))

    print("\nCategories:")
    for i, category in enumerate(categories, start=1):
        print(f"{i}. {category}")

    choice = input("\nSelect a category by number: ")
    if not choice.isdigit() or int(choice) < 1 or int(choice) > len(categories):
        print("Invalid choice. Returning to main menu.")
        return

    selected_category = categories[int(choice) - 1]
    print(f"\nTools in '{selected_category}':\n")
    for tool in tools:
        if tool["category"] == selected_category:
            print(f"- {tool['name']} ({tool['url']})\n  {tool['desc']}")

# Function to search for a tool by name
def search_tool(tools):
    query = input("\nEnter the tool name to search for: ").lower()

    results = [tool for tool in tools if query in tool["name"].lower()]
    if results:
        print("\nSearch Results:")
        for tool in results:
            print(f"- {tool['name']} ({tool['url']})\n  {tool['desc']}")
    else:
        print("\nNo tools found with that name.")

# Function to open a tool's URL in the default web browser
def open_tool_url(tools):
    query = input("\nEnter the tool name to open: ").lower()

    for tool in tools:
        if query in tool["name"].lower():
            print(f"Opening {tool['name']} in your web browser...")
            webbrowser.open(tool["url"])
            return

    print("\nTool not found.")

# Main menu
def main_menu(tools):
    while True:
        print("\nAndroid Security Tools CLI")
        print("1. List tools by category")
        print("2. Search for a tool")
        print("3. Open a tool's webpage")
        print("4. Exit")

        choice = input("\nEnter your choice: ")

        if choice == "1":
            list_tools_by_category(tools)
        elif choice == "2":
            search_tool(tools)
        elif choice == "3":
            open_tool_url(tools)
        elif choice == "4":
            print("Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")

# Entry point
if __name__ == "__main__":
    if not os.path.exists(README_FILE):
        print(f"Error: {README_FILE} not found. Please ensure the script is in the same directory as the README.md file.")
    else:
        tools = parse_tools(README_FILE)
        main_menu(tools)
