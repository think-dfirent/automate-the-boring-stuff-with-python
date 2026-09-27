from urllib.parse import parse_qs, urlsplit

from playwright.sync_api import sync_playwright


def search_verified_attacks(page):
    page.locator("i.iconfont.nx-search.cursor-pointer:visible").click()
    # Options load asynchronously and reset the menu when they arrive.
    attack = page.locator(".opddos-cascader-li.second-arrow").filter(
        has=page.locator(".icon-is-attack.material-icons")
    )
    attack.wait_for(state="attached", timeout=15000)
    page.get_by_role("button", name="All Tags", exact=True).click()
    attack.filter(visible=True).click(timeout=15000)

    verified = page.get_by_text("Verified Attack", exact=True).filter(visible=True)
    verified.click(timeout=15000)
    selected_tag = page.get_by_role("button", name="Verified Attack", exact=True)
    selected_tag.wait_for(state="visible", timeout=5000)

    print("Verified Attack selected")
    # The sidebar has a different button whose accessible name is also Search.
    search_btn = page.locator('.search-btn[ng-click="searchEssential()"]:visible')
    print("Search btn found: ", search_btn.count())
    with page.expect_response(
        lambda response: urlsplit(response.url).path.endswith("/ddos_event_search_v2")
        and parse_qs(urlsplit(response.url).query).get("tag_key")
        == ["verified_attack"],
        timeout=30000,
    ) as search_response:
        search_btn.click()
    response = search_response.value
    response.body()
    if not response.ok:
        raise RuntimeError(f"Verified Attack search failed: HTTP {response.status}")
    print("Verified Attack search completed")


def main():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False)
        context = browser.new_context(storage_state="nexusguard_state.json")
        page = context.new_page()
        page.goto("https://support.nexusguard.com")

        skip = page.get_by_text("Skip", exact=True)
        print("Skip matches:", skip.count())
        if skip.count() > 0 and skip.is_visible():
            skip.click()

        cmc = page.get_by_text("CMC_Global_Offload", exact=True).first
        cmc.wait_for(state="visible", timeout=15000)

        context.storage_state(path="nexusguard_state.json")
        print("Session saved")

        print("CMC matches:", cmc.count())
        cmc.click()

        alert = page.get_by_text("DDoS Alert", exact=True).first
        alert.wait_for(state="visible", timeout=15000)
        print("DDOS alert matches: ", alert.count())
        alert.click()

        search_verified_attacks(page)
        input("Press Enter to close browser...")
        browser.close()


if __name__ == "__main__":
    main()
