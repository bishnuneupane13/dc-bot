import discord
import io
import asyncio
import os
from typing import Optional
from playwright.async_api import async_playwright

async def capture_screenshot(url: str, filename: str = "screenshot.png") -> Optional[discord.File]:
    """
    Capture a screenshot of a URL using Playwright.
    Returns a discord.File object or None if failed.
    """
    try:
        if not url.startswith(('http://', 'https://')):
            url = f'http://{url}'
            
        async with async_playwright() as p:
            # Launch browser (this will fail if not installed, we catch it)
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page(viewport={'width': 1280, 'height': 720})
            
            # Navigate with timeout
            try:
                await page.goto(url, timeout=15000, wait_until="networkidle")
            except:
                # Even if full load fails, try capturing what's there
                pass
                
            screenshot_bytes = await page.screenshot(full_page=False)
            await browser.close()
            
            return discord.File(io.BytesIO(screenshot_bytes), filename=filename)
            
    except Exception as e:
        print(f"Screenshot error: {e}")
        # Check if it's the "browsers not installed" error
        if "Executable doesn't exist" in str(e) or "playwright install" in str(e):
             print("Playwright browsers not installed. Please run: playwright install chromium")
        return None

async def install_browsers():
    """Helper to install browsers if needed"""
    if os.name == 'nt':
        cmd = "playwright install chromium"
        process = await asyncio.create_subprocess_shell(
            cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        return process.returncode == 0
    return False
