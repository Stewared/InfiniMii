# InfiniMii SEO Testing Checklist

## Pre-Launch Testing

### 1. Structured Data Validation
- [ ] Test all pages with [Google Rich Results Test](https://search.google.com/test/rich-results)
- [ ] Validate schema with [Schema Markup Validator](https://validator.schema.org/)
- [ ] Check individual Mii pages for CreativeWork schema
- [ ] Verify Organization schema on homepage
- [ ] Test FAQ schema on guides pages

### 2. Mobile Friendliness
- [ ] Test with [Google Mobile-Friendly Test](https://search.google.com/test/mobile-friendly)
- [ ] Verify responsive design on actual devices
- [ ] Check touch target sizes
- [ ] Test on iOS Safari and Android Chrome

### 3. Core Web Vitals
- [ ] Run [PageSpeed Insights](https://pagespeed.web.dev/) for key pages:
  - [ ] Homepage (/)
  - [ ] Individual Mii page (/mii/[id])
  - [ ] Browse pages (/top, /recent, /official)
  - [ ] Upload page (/upload)
  - [ ] Convert page (/convert)
- [ ] Target scores:
  - [ ] LCP < 2.5s
  - [ ] INP < 200ms
  - [ ] CLS < 0.1
- [ ] Test on both mobile and desktop

### 4. Sitemap Validation
- [ ] Access /sitemap.xml - verify it loads
- [ ] Access /sitemap-miis.xml - verify Mii URLs
- [ ] Access /sitemap-users.xml - verify user URLs
- [ ] Check /robots.txt - verify sitemap references
- [ ] Submit sitemaps to Google Search Console
- [ ] Submit sitemaps to Bing Webmaster Tools

### 5. Canonical URLs
- [ ] Verify canonical tags on all pages
- [ ] Check for duplicate content issues
- [ ] Ensure old URLs redirect with 301

### 6. Open Graph Tags
- [ ] Test with [Facebook Sharing Debugger](https://developers.facebook.com/tools/debug/)
- [ ] Test with [Twitter Card Validator](https://cards-dev.twitter.com/validator)
- [ ] Verify images load correctly (1200x630px minimum)
- [ ] Check all meta descriptions are unique and compelling

### 7. Internal Linking
- [ ] Verify footer links work on all pages
- [ ] Check breadcrumb navigation
- [ ] Test sidebar links
- [ ] Verify no broken internal links

### 8. Performance
- [ ] Check image compression
- [ ] Verify lazy loading works
- [ ] Test page load times
- [ ] Check compression middleware is working
- [ ] Verify caching headers are set correctly

### 9. Accessibility
- [ ] Run [WAVE accessibility checker](https://wave.webaim.org/)
- [ ] Verify all images have alt text
- [ ] Check heading hierarchy (H1, H2, H3)
- [ ] Test keyboard navigation
- [ ] Verify ARIA labels on interactive elements

### 10. Search Console Setup
- [ ] Add property to Google Search Console
- [ ] Verify ownership
- [ ] Submit sitemaps
- [ ] Check for crawl errors
- [ ] Monitor Core Web Vitals report

## Post-Launch Monitoring (Daily)

### Week 1-4
- [ ] Check Google Search Console for errors
- [ ] Monitor Core Web Vitals performance
- [ ] Review indexing status
- [ ] Check for 404 errors
- [ ] Monitor site speed

### Monthly
- [ ] Review top performing pages
- [ ] Analyze search queries
- [ ] Check backlink profile
- [ ] Update content based on performance
- [ ] Review and fix any technical SEO issues

## Key URLs to Test

1. Homepage: https://infinimii.com/
2. Top Miis: https://infinimii.com/top
3. Official Miis: https://infinimii.com/official
4. Sample Mii: https://infinimii.com/mii/[sample-id]
5. User Profile: https://infinimii.com/user/[sample-user]
6. Convert: https://infinimii.com/convert
7. Upload: https://infinimii.com/upload
8. Search: https://infinimii.com/search
9. Guide: https://infinimii.com/guides/transfer
10. About: https://infinimii.com/about