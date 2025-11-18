from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.prompts import PromptTemplate
from langchain_core.output_parsers import StrOutputParser

llm = ChatOpenAI(
    api_key="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",
    base_url="https://openrouter.ai/api/v1",
    model="openrouter/sherlock-think-alpha",
    default_headers={ 
    }
)



classifer = ChatPromptTemplate.from_messages([
    ("system","You are a world class comedian."),
    ("human", "Tell me  a joke about {topic}")
])

response = classifer.invoke({"topic": "llm"})
print(response)

chain = classifer | llm

chain.invoke({"topic": "llm"})
response = chain | StrOutputParser()
print(response) 

