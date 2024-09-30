# BugBeacon
A web-scraping tool designed to search and report Critical and High Severity Vulnerabilities for OEM equipment from official OEM websites and other relevant platforms. The tool automates vulnerability tracking and delivers real-time alerts.

# SIH submission

Abstract

In the realm of critical infrastructure, the timely dissemination of information regarding software and hardware vulnerabilities is crucial to maintaining operational security. Currently, vulnerability information from Original Equipment Manufacturers (OEMs) and software vendors is often delayed when published through platforms such as the National Vulnerability Database (NVD), which can leave critical systems exposed to threats for longer than necessary. The proposed solution aims to tackle this gap by implementing an automated, real-time system that monitors vendor security advisories, scrapes vulnerability information directly from these sources, and disseminates timely alerts to relevant stakeholders. This solution leverages advanced web scraping, cloud-based infrastructure, and Large Language Models (LLMs) to ensure that critical vulnerabilities are promptly communicated to affected organizations, significantly reducing the time between vulnerability disclosure and remediation.

To begin, a database of vendors and their security advisory pages will be established, with entries populated by scraping the NVD and manually supplementing vendor information as needed. This database will continuously grow and update as new vulnerabilities emerge. The monitoring process will involve periodic lookups on the vendor advisories to detect changes indicative of newly disclosed vulnerabilities. A distributed network of AWS Lambda functions will be utilized to carry out this monitoring process efficiently, triggering scraping tasks when new advisories are detected. This architecture ensures scalability and low-latency response times by leveraging AWS Lambda’s event-driven capabilities.

Once new vulnerability information is detected, AWS Lambda will trigger a scraping process to extract the raw content from the advisory pages. This raw content will then be sent to an LLM deployed via AWS SageMaker or AWS Bedrock for processing. SageMaker provides the flexibility to train, fine-tune, and deploy LLMs capable of understanding the structure of security advisories and extracting key information such as product name, version, severity level, vulnerability details, and mitigation strategies. AWS Bedrock, on the other hand, offers ready-made foundation models that simplify integration and reduce the time to deployment. The LLM, accessed through these AWS services, will be responsible for structuring the extracted information into a well-defined format suitable for notification purposes. The deployment of LLMs on scalable AWS infrastructure ensures both high performance and adaptability to varying workloads, which is particularly important as the volume of vulnerability disclosures fluctuates over time.

After processing the advisory information, the LLM will generate a structured, human-readable message that captures all critical aspects of the vulnerability. This message will be formatted according to a predefined template, ensuring consistency in communication. The AWS Simple Email Service (SES) will be used to dispatch these notifications to subscribed users in near real-time. Users will also be able to manage their subscriptions through a web portal, allowing them to choose which vendors they wish to receive alerts from, ensuring relevance and reducing information overload. This overall approach results in faster dissemination of vulnerability alerts compared to waiting for NVD updates, as advisories are scraped directly from vendor pages shortly after publication.

The proposed solution integrates various modern technologies to ensure a comprehensive, robust, and real-time vulnerability monitoring and alerting system. By leveraging AWS cloud infrastructure, web scraping, and LLM-based data processing, this system aims to mitigate the risk posed by unpatched vulnerabilities in critical systems by drastically reducing the delay between vulnerability publication and the receipt of actionable information. This proactive approach enhances the cybersecurity posture of critical sector organizations, ensuring they are alerted to emerging threats in the shortest possible time, empowering them to mitigate risks effectively and protect their infrastructure from potential exploitation.


Idea Description

In today's digital age, the infrastructure of critical sector organizations, encompassing utilities, transportation, finance, healthcare, and more, relies heavily on a wide variety of IT and Operational Technology (OT) components. These components include networking devices, hardware, operating systems, and various software applications. Such reliance also means these components are exposed to potential security threats in the form of vulnerabilities—bugs or flaws that can be exploited by malicious actors to compromise system integrity, confidentiality, or availability.

These vulnerabilities often come with different levels of severity, categorized as Critical, High, Medium, or Low, based on their potential impact. Given the highly sensitive nature of critical infrastructure, even a minor security gap can lead to severe repercussions. Therefore, it is crucial to ensure timely identification and mitigation of these vulnerabilities.

While many organizations rely on publicly available sources of vulnerability information like the National Vulnerability Database (NVD), such databases have inherent limitations. One key drawback is the delay between a vulnerability being reported by the Original Equipment Manufacturer (OEM) and it being published in NVD. This time lag, sometimes ranging from hours to days, can significantly increase the risk of exploitation, especially for vulnerabilities classified as Critical or High. Furthermore, critical sector organizations may use equipment from multiple OEMs, and vulnerabilities affecting such equipment are often published on vendor-specific security advisories, which may not be captured by a single centralized source. 

To address these limitations, we propose an automated solution that provides real-time monitoring of vendor-specific vulnerability advisories, coupled with fast and efficient notification mechanisms to alert registered users to newly published vulnerabilities. Our proposed solution aims to bridge the gap between OEM publication and centralized databases like NVD by directly scraping vulnerability information from vendor advisories and other relevant sources in real-time. This approach helps ensure that critical sector organizations are informed promptly about potential threats, allowing them to take mitigating actions without delay.

The solution involves multiple interconnected components to effectively automate the collection, monitoring, processing, and dissemination of vulnerability information:

1. Vendor Database Creation: A foundational step in our approach is building a dynamic database of vendors that publish security advisories. To achieve this, we propose leveraging web scraping techniques to extract backlinks to vendor advisories from the NVD database. This provides an initial list of vendors with known vulnerabilities. However, not all vendors may provide backlinks or be listed comprehensively in NVD, and in such cases, we plan to manually supplement our database to ensure all critical vendors are included. The vendor database will be continuously updated as new CVEs (Common Vulnerabilities and Exposures) are published, providing a comprehensive source for subsequent monitoring.

2. Real-Time Monitoring with Web Scrapers: To ensure timely detection of new vulnerabilities, we will deploy distributed web scrapers designed to detect changes on vendor-specific advisory pages. AWS Lambda, a serverless computing solution, will be used to deploy these scrapers for quick and efficient execution whenever a vulnerability advisory is updated. The use of AWS Lambda not only allows for efficient resource utilization but also ensures that monitoring can be done at scale and in real time, which is critical for reducing the time between vulnerability disclosure and alert generation. By monitoring directly at the source—the vendor advisories—we can significantly reduce the delay compared to waiting for centralized databases like NVD to update.

3. Information Extraction & Processing: Once a new vulnerability is detected on a vendor advisory page, the next step is to extract relevant details, such as the product name, version, severity, description of the vulnerability, and mitigation strategy. Extracting this information accurately is essential for preparing meaningful notifications for end users. To achieve this, we propose utilizing a Large Language Model (LLM) for information extraction and processing. The LLM will intelligently parse the text available on the advisory page and format it into a structured message that can be used for notifications. This step allows us to present complex technical information in a simplified and consistent manner, tailored to the needs of the target audience.

4. Fast Email Alerts: After the relevant information is extracted and processed, the next component of our solution involves notifying users. Email remains one of the most effective and direct means of communication for security notifications, especially in critical sectors where fast decision-making is required. We will use AWS Simple Email Service (SES) to send email alerts in real-time to subscribed users. Each alert will contain all the essential details of the newly published vulnerability, including the severity, affected products, and recommended mitigation actions. By providing alerts at the same time (or before) a CVE is published on NVD, our solution empowers organizations to take mitigating actions earlier, thereby reducing the risk window.

5. User-Friendly Web Portal: To ensure ease of use and provide complete access to our solution, we propose building a user-friendly web portal that serves as the main interface for users. Through this portal, users can register for alerts, select specific vendors or products they are interested in monitoring, and view a history of vulnerabilities affecting the vendors they follow. This customization ensures that users only receive relevant notifications, reducing information overload while enhancing efficiency.

Our solution aims to provide a comprehensive and proactive vulnerability monitoring system that is faster and more efficient than traditional centralized databases like NVD. By directly scraping information from vendor advisories, leveraging distributed web scraping through AWS Lambda, and deploying advanced information processing techniques using LLMs, our system will provide real-time alerts to critical sector organizations, enabling them to respond quickly to emerging threats and reduce their cybersecurity risks.

This integrated approach provides several key benefits, including:

1. Reduced Time Lag: Monitoring vendor advisories directly eliminates the delay between OEM publication and NVD listing, giving organizations a head start in addressing vulnerabilities.

2. Real-Time Alerts: By utilizing serverless computing, we can ensure that any update on a vendor advisory page triggers an alert within moments, providing real-time insights to subscribed users.

3. Efficient Information Processing: Leveraging LLMs allows us to accurately parse complex vulnerability information and present it in a structured, easy-to-read format for users.

4. Scalable Solution: The use of AWS Lambda ensures that our system is highly scalable, capable of monitoring numerous vendor sites without requiring manual intervention or significant computational overhead.

5. Customizable Subscriptions: By offering a web portal for subscription management, we provide users with a personalized experience that ensures they are notified about the vulnerabilities most relevant to their needs.

Through this solution, we aim to create an effective, automated, and proactive vulnerability monitoring system that empowers critical sector organizations to enhance their cybersecurity posture, ultimately reducing the risks of exploitation and enabling timely action in response to newly discovered vulnerabilities.

In Depth Discussion

What is Common Vulnerabilities and Exposures (CVE)?

The Common Vulnerabilities and Exposures (CVE) system is a widely recognized standard that identifies publicly known cybersecurity vulnerabilities. The CVE system assigns unique identifiers to vulnerabilities and exposures found in software, hardware, and firmware. These identifiers, known as CVE IDs, consist of a unique number and are used globally to ensure a consistent and standardized way of referencing vulnerabilities. For instance, a CVE ID like "CVE-2023-12345" represents a specific vulnerability, providing a common reference point for security experts, developers, and organizations worldwide.

CVE IDs are essential because they allow people to communicate clearly about vulnerabilities without confusion. By using the same identifier, anyone in the field of cybersecurity can easily look up a vulnerability, understand its impact, and check whether it has been patched or mitigated. The CVE program is managed by the MITRE Corporation in collaboration with a community of trusted organizations known as CVE Numbering Authorities (CNAs). When a new vulnerability is discovered, the CNA verifies its legitimacy, assigns it a CVE ID, and publishes the necessary details about the vulnerability.

However, CVEs provide only an identifier, a brief description, and reference links. They do not contain detailed mitigation information, which is critical for system administrators and IT teams to take action. This is where security advisories and comprehensive vulnerability databases come into play.

What is National Vulnerability Database (NVD)?

The National Vulnerability Database (NVD) is a public repository operated by the National Institute of Standards and Technology (NIST) in the United States. It builds on the CVE system by providing additional information, including severity metrics, impact scores, detailed descriptions, and suggested remediation or mitigation steps. The NVD is closely tied to the CVE program; each CVE ID that is assigned by MITRE gets enriched with this extra information by NVD, making it a crucial resource for security teams and organizations looking to protect their assets.

NVD uses the Common Vulnerability Scoring System (CVSS) to provide a severity score for each vulnerability, categorizing them as Critical, High, Medium, or Low. This score is essential for helping organizations prioritize which vulnerabilities to address first based on their potential impact.

However, there is an inherent limitation in NVD that we aim to address in our solution—timeliness. The process of assigning a CVE ID, enriching it with detailed information, and then making it available to the public often leads to a time lag between the disclosure of a vulnerability and its publication in NVD. This delay, which could range from hours to several days, leaves organizations vulnerable. During this time lag, attackers can exploit the vulnerabilities before organizations even become aware of them through NVD updates. Additionally, NVD aggregates information from multiple vendors, which sometimes delays the availability of the latest updates or advisories published by the Original Equipment Manufacturers (OEMs).

What are OEM Security Advisories?

OEMs play a significant role in keeping systems secure by publishing security advisories directly on their websites. These advisories are official notifications released by OEMs—such as Microsoft, Google, Cisco, or Siemens—informing their customers about vulnerabilities in their products, along with mitigation measures, patches, or workarounds. Unlike the centralized repositories like NVD, these advisories are typically published as soon as a vulnerability is identified, and remediation measures are available, thereby offering the earliest possible alert about potential threats.

Security advisories from OEMs are an authoritative source of information because they come directly from the manufacturers of the affected products. These advisories typically include detailed information, such as:

    Product Name and Version: The affected product and the specific versions that contain the vulnerability.
    Vulnerability Details: A description of the vulnerability, including how it can be exploited and its potential impact.
    Severity Level: The criticality of the vulnerability, which is often categorized using internal or widely accepted scoring systems like CVSS.
    Mitigation Strategy: Steps that users can take to mitigate the impact of the vulnerability, such as applying patches or changing configuration settings.
    Release Dates and Relevant Links: The date of publication and links to additional resources or related advisories.

One challenge with OEM security advisories is that each OEM might have different formats and structures for publishing these notifications, and there is no standardized template across the industry. Some advisories are simple text announcements, while others may be complex webpages with multiple links, charts, and references. Additionally, some vendors may not publish advisories in a consistent manner, making it difficult to monitor them manually for changes or updates.

To overcome these challenges and ensure critical sector organizations can act quickly upon the release of new advisories, our solution will create a database of OEMs and vendor-specific advisories. This database will help automate the monitoring process and streamline the collection of information in real time.

Creating the Vendor Database:

Our proposed solution begins with the creation of a comprehensive and dynamic database of vendors and their corresponding security advisory URLs. The steps involved in this process include:

1) Scraping NVD for Vendor Backlinks: The NVD website includes references to vendor-specific advisories in its CVE entries. We propose scraping the NVD database using Python libraries such as Beautiful Soup or Scrapy to gather backlinks from CVE descriptions. These backlinks often point to the vendor's security advisories, where the OEM has provided detailed information about the vulnerability. By scraping these backlinks, we can extract a list of URLs pointing to the pages where vulnerabilities are published, creating a database of vendors and their advisories. This process will be automated to ensure that each new CVE entry is used to update the database continuously.

2) Manual Supplementation: Not all vendors provide backlinks in NVD, and in some cases, the provided links may be incomplete or lead to generic pages rather than specific advisories. In such cases, we will manually identify and add the correct URLs to our database. This step ensures that our vendor database is as comprehensive as possible, covering all critical vendors relevant to our target audience in critical sectors.

3) Database Maintenance and Updates: The vendor database must be kept up-to-date to remain effective. As new vulnerabilities are published on NVD, our system will scrape and update the vendor information, ensuring that our web scrapers can accurately target the relevant advisory pages in the future. This automated, continuous updating process will help ensure that no vulnerabilities go unnoticed.

Once the vendor database is created, it serves as the foundation for real-time monitoring. By directly monitoring vendor-specific security advisories, we can detect newly published vulnerabilities and mitigation steps without waiting for the centralized aggregation process of NVD. This proactive approach significantly reduces the window of vulnerability by alerting critical sector organizations to new threats as soon as the OEM discloses them.

Technical Approach for Continuous Monitoring:

To achieve continuous monitoring of vendor security advisories, we will employ a combination of distributed web scraping, AWS Lambda for compute-on-demand, and AWS CloudWatch for interval-based triggers. Below is a detailed breakdown of how we plan to technically implement this solution:

1. Interval-Based Monitoring Using AWS CloudWatch Events:

The first step in the process involves setting up a mechanism to periodically check for updates on vendor advisory pages. Instead of having our scrapers run constantly, which would be resource-intensive and costly, we will use a more efficient approach by configuring interval-based checks.

- AWS CloudWatch Events for Scheduled Lookups:
  AWS CloudWatch Events (also known as Amazon EventBridge) will be used to create scheduled rules that define specific time intervals for our system to perform lookups. For example, we could schedule these checks to run every 15 minutes or even more frequently, depending on the criticality and frequency of new CVE releases by the vendors.
  
  CloudWatch Events can trigger an AWS Lambda function at defined intervals, ensuring the system runs periodically and remains scalable. These triggers help keep our solution cost-effective since compute resources are used only when necessary.

- Granularity and Optimization:
  Depending on the importance of specific vendors and their products, we may decide to configure different intervals for different security advisories. For example, vendors with a high frequency of updates or those that are deemed particularly critical (such as vendors in the network security or operating systems domain) could be monitored more frequently compared to others.

2. Triggering the AWS Lambda Function for Scraping:

Once the CloudWatch Event is triggered, it will invoke an AWS Lambda function that is responsible for carrying out the actual web scraping task.

- Scraping Logic:
  The Lambda function will contain a scraping script, built using libraries such as Beautiful Soup or Scrapy, to extract relevant information from the vendor advisory pages. Each Lambda invocation will:
    - Make an HTTP request to the vendor's advisory page.
    - Parse the page's HTML to look for CVE entries and their associated information.
    - Compare the extracted CVEs with previously stored information to determine if any new CVE entries have been published.

- Handling State and Changes:
  To keep track of which CVEs have already been recorded, we need to maintain a persistent state across function invocations. This can be achieved by using a storage service like AWS DynamoDB or Amazon S3 to store details about each advisory, including the list of CVEs and the last timestamp they were checked. When the Lambda function runs, it will:
    - Fetch the current list of CVEs from the vendor's advisory.
    - Compare it with the previously recorded CVEs (retrieved from DynamoDB or S3).
    - Identify any new CVEs that were not present in the previous version.

  If new CVEs are identified, the Lambda function will pass these new entries along with their extracted information (product name, version, severity, mitigation strategies, etc.) to the next stage of processing for notification purposes.

3. Efficiency and Scalability Using Distributed Scraping:

Given the wide range of vendors and security advisories we are monitoring, a single Lambda function may not be sufficient to handle all vendors simultaneously. Instead, we will employ a distributed scraping approach.

- Lambda for Different Vendors:
  We can create multiple instances of Lambda functions, each responsible for a subset of vendor advisory pages. By leveraging the scalability of Lambda, we can dynamically scale the number of scraping functions depending on the number of vendors to be monitored. This distributed approach ensures that our solution can efficiently handle large numbers of vendors without running into execution time limits, which is especially important when dealing with long-running scraping operations.

- Concurrency Control:
  AWS allows for concurrency limits to be set on Lambda functions to prevent resource overuse. We can use these concurrency controls to ensure that our Lambda invocations are balanced across the number of vendor advisories being monitored, avoiding the risk of rate-limiting or being blacklisted by the vendor’s website for excessive requests.

4. Optimizing Web Scraping to Reduce Load:

To minimize the risk of being blocked by vendor websites, we will implement several optimization strategies:

- Conditional Requests Using HTTP Headers:
  The Lambda scraping script will use conditional GET requests with HTTP headers such as `If-Modified-Since` or `ETag`. These headers will check whether the content on the page has changed since the last visit. If the page hasn't changed, there will be no need to parse the content, reducing unnecessary load on both our system and the vendor’s website.

- Caching Data and Rate-Limiting:
  We will also implement caching mechanisms to store recently accessed data, reducing redundant requests to the same advisory pages. Additionally, rate-limiting techniques will be used to ensure our requests do not overwhelm vendor servers. This approach helps prevent IP bans, ensuring that our scraper can continue to function smoothly over time.

5. Handling Web Page Structure Variability with Vendor-Specific Logic:

As each vendor may have its own way of structuring advisory pages, our scraping scripts will need to be flexible:

- Vendor-Specific Scrapers:
  Depending on the structure of each vendor’s page, we may create separate scraping logic for different vendors. For some vendors, scraping might involve parsing JSON data, while for others it could mean navigating an HTML table. The scraping logic will need to be customized based on the format of each advisory.

- Machine Learning or Rule-Based Parsing:
  For vendors that use dynamic or frequently changing advisory formats, we could potentially use machine learning models or LLMs to identify the relevant sections of the page automatically. These models could be trained to detect key information like product names, versions, and mitigation strategies, making the scraping more resilient to minor changes in page layouts.

6. Managing and Maintaining the Vendor Database:

To ensure the accuracy of our monitoring, we must also maintain the vendor database:

- Constant Automatic Updates:
  We will ensure that new vendors and advisory pages are added automatically as new CVEs are published by using a similar event based scrapping. The scraper will extract backlinks from NVD entries, adding new URLs to the vendor database as they become available.
  
- Manual Updates:
  For vendors that do not have structured backlinks in the NVD, we will manually add and verify advisory URLs periodically. This ensures our database remains comprehensive and does not miss any critical advisory pages.

Deployment and Usage of LLMs for Information Extraction:

To ensure that the generated notifications are accurate, well-structured, and provide all critical details, we will leverage Large Language Models (LLMs) to extract information from the scraped vendor security advisories and format it into a standardized message. The LLMs will be deployed using AWS infrastructure, specifically focusing on AWS SageMaker, which offers scalable solutions for deploying machine learning models.

AWS SageMaker is a fully managed service that makes it easier to build, train, and deploy machine learning models. We will use SageMaker to deploy and host our LLM for information extraction and formatting. Below is a detailed overview of how SageMaker will be utilized:

Model Deployment on AWS SageMaker:

    Training and Customizing the LLM: Depending on the specific requirements of the scraped data, we may need to fine-tune a pre-existing LLM to understand the structure and details of CVE entries on different vendor websites. Using SageMaker, we can fine-tune an open-source LLM (e.g., GPT-3, LLaMA, or similar) using a dataset consisting of annotated vulnerability advisories. This training step helps the model become better at identifying fields such as "Product Name," "Version," "Severity Level," "Mitigation Strategy," etc.

    Model Hosting: After training, we will use SageMaker to deploy the LLM as an endpoint. This endpoint will be accessible through an API, allowing our Lambda functions (which are responsible for scraping vendor advisories) to send raw scraped text for processing. This setup ensures that we can easily integrate the LLM into our overall architecture, enabling real-time processing of scraped data.

    Batch Transform and Real-Time Inference: SageMaker offers two primary methods for using deployed models—batch transform for large datasets and real-time inference for immediate processing. For our use case, we will rely on real-time inference. Whenever a new vulnerability is detected, the Lambda function will invoke the SageMaker endpoint to extract relevant details from the scraped data and format it for further use.

Integration Workflow:

    Triggering Information Extraction: When our scraper detects a new CVE on a vendor advisory page, the raw scraped text will be sent to the SageMaker LLM endpoint via an API request. This text will typically be in HTML or raw text format containing various details about the vulnerability.

    LLM-Based Information Extraction: The LLM deployed on SageMaker will process the input text to extract the necessary information, such as:
        Product name
        Product version (if applicable)
        Vendor name
        Severity level (Critical, High, Medium, Low)
        Description of the vulnerability
        Mitigation strategy
        Published date
        Unique CVE ID

    The model will be trained or fine-tuned to understand common patterns across different advisories, ensuring high accuracy in extracting these fields. The output will be a structured JSON containing all relevant information that can be easily used to compose an email alert.

    Formatting the Notification: After extracting the relevant details, the LLM will also generate a concise, human-readable message. This message will be formatted based on a predefined template (e.g., including details such as mitigation links, severity level, etc.) to ensure consistency. The message will then be forwarded to the AWS SES service for emailing subscribed users.
