# Finance

Finance, a web app via which you can manage portfolios of stocks. Its shows real time stock prices of company and lets you "sell" and "buy" stocks.

[Visit here](https://finance-quote-buy-sell-shares.herokuapp.com/login)

## To run app locally
first
```
pip install -r requirements.txt
```
then set environment varibles
```
export FLASK_APP=application.py
export DATABASE_URL = # database url of postgresql
```

to use api and quote stock from [iex](https://iexcloud.io/), you need to make an account and then get api key (publishable one) from token in [console](https://iexcloud.io/console/tokens).

after getting *api_key* do
```
export API_KEY=<you api key>
```
now, last step is to run app by executing below
```
flask run
```