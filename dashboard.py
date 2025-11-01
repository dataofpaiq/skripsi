import requests
import pandas as pd
import plotly.express as px
from dash import dcc, html, Dash, dash_table
from dash.dependencies import Input, Output
from flask import request
from collections import deque
import json
import dash_bootstrap_components as dbc
from datetime import datetime

# Initialize Dash App with Bootstrap theme
app = Dash(__name__, external_stylesheets=[dbc.themes.COSMO])
server = app.server  # for Flask access

# Prediction buffer (real-time)
flow_buffer = deque(maxlen=50)  # store last 50 flows

# ONOS REST API URL
BASE_URL = "http://localhost:8181/onos/v1/statistics/delta/ports"

# Function to get device IDs from ONOS
def get_device_ids():
    url = "http://localhost:8181/onos/v1/devices"
    try:
        response = requests.get(url, auth=("onos", "rocks"))
        if response.status_code == 200:
            devices = response.json()["devices"]
            return [device["id"] for device in devices]
    except:
        return []
    return []

# Function to get ports by Device ID
def get_ports(device_id):
    url = f"http://localhost:8181/onos/v1/devices/{device_id}/ports"
    try:
        response = requests.get(url, auth=("onos", "rocks"))
        if response.status_code == 200:
            ports = response.json()["ports"]
            return [port["port"] for port in ports if "port" in port]
    except:
        return []
    return []

# Function to get traffic statistics
def get_traffic(device_id, port):
    url = f"{BASE_URL}/{device_id}/{port}"
    try:
        response = requests.get(url, auth=("onos", "rocks"))
        if response.status_code == 200:
            data = response.json()
            for stat in data.get("statistics", []):
                if stat["device"] == device_id:
                    for p in stat.get("ports", []):
                        if str(p["port"]) == str(port):
                            return {
                                "bytesSent": p.get("bytesSent", 0),
                                "bytesReceived": p.get("bytesReceived", 0),
                                "packetsSent": p.get("packetsSent", 0),
                                "packetsReceived": p.get("packetsReceived", 0),
                                "timestamp": datetime.now().strftime("%H:%M:%S")
                            }
    except:
        return {
            "bytesSent": 0, 
            "bytesReceived": 0, 
            "packetsSent": 0, 
            "packetsReceived": 0,
            "timestamp": datetime.now().strftime("%H:%M:%S")
        }
    return {
        "bytesSent": 0, 
        "bytesReceived": 0, 
        "packetsSent": 0, 
        "packetsReceived": 0,
        "timestamp": datetime.now().strftime("%H:%M:%S")
    }

# Endpoint to receive data from flow_session.py
@server.route("/flow-prediction", methods=["POST"])
def receive_flow():
    data = request.json
    if data:
        data["timestamp"] = datetime.now().strftime("%H:%M:%S")
        flow_buffer.appendleft(data)  # Add to top
        return {"status": "received"}, 200
    return {"error": "no data"}, 400

# Initial empty data
df = pd.DataFrame(columns=['Time', 'bytesSent', 'bytesReceived', 'packetsSent', 'packetsReceived', 'timestamp'])

# Initialize Dash App with custom color palette
app = Dash(__name__, external_stylesheets=[dbc.themes.BOOTSTRAP])
server = app.server

# Custom color palette from user's request
color_palette = {
    'raisin_black': '#161925',
    'delft_blue': '#23395B',
    'ucla_blue': '#406E8E',
    'powder_blue': '#8EA8C3',
    'mint_green': '#CBF7ED',
    'white': '#FFFFFF',
    'light_gray': '#F8F9FA'
}

app.layout = dbc.Container(fluid=True, style={
    'background-color': color_palette['light_gray'],
    'min-height': '100vh',
    'padding': '20px'
}, children=[
    # Header with new color scheme
    dbc.Row([
        dbc.Col([
            html.Div([
                html.H1("SDN Traffic Monitoring Dashboard", 
                       style={
                           'color': color_palette['delft_blue'],
                           'fontWeight': '600',
                           'marginBottom': '0.5rem'
                       }),
                html.P("Real-time network traffic visualization", 
                      style={
                          'color': color_palette['ucla_blue'],
                          'fontStyle': 'italic'
                      })
            ], style={
                'textAlign': 'center', 
                'marginBottom': '2rem',
                'padding': '1.5rem',
                'background-color': color_palette['white'],
                'border-radius': '8px',
                'box-shadow': '0 2px 4px rgba(0,0,0,0.1)'
            })
        ])
    ]),
    
    # Main content area
    dbc.Row([
        # Left column - Controls and metrics
        dbc.Col(md=4, children=[
            # Device selection card
            dbc.Card([
                dbc.CardHeader("Device Configuration", 
                              style={
                                  'backgroundColor': color_palette['delft_blue'],
                                  'color': color_palette['white'],
                                  'fontWeight': '500',
                                  'border-radius': '8px 8px 0 0 !important'
                              }),
                dbc.CardBody([
                    html.Label("Select Device ID", 
                             style={
                                 'color': color_palette['raisin_black'],
                                 'marginBottom': '0.5rem',
                                 'fontWeight': '500'
                             }),
                    dcc.Dropdown(
                        id='device-id',
                        options=[{'label': i, 'value': i} for i in get_device_ids()],
                        placeholder="Select device...",
                        style={
                            'marginBottom': '1.5rem',
                            'borderRadius': '4px',
                            'borderColor': color_palette['powder_blue']
                        }
                    ),
                    html.Label("Select Port", 
                             style={
                                 'color': color_palette['raisin_black'],
                                 'marginBottom': '0.5rem',
                                 'fontWeight': '500'
                             }),
                    dcc.Dropdown(
                        id='port-id',
                        options=[],
                        placeholder="Select port...",
                        style={
                            'borderRadius': '4px',
                            'borderColor': color_palette['powder_blue']
                        }
                    )
                ])
            ], className="shadow", style={
                'borderRadius': '8px',
                'border': 'none',
                'marginBottom': '1.5rem',
                'position' : 'relative',
            }
            ),
            
            # Traffic metrics card
            dbc.Card([
                dbc.CardHeader("Current Traffic", 
                             style={
                                 'backgroundColor': color_palette['ucla_blue'],
                                 'color': color_palette['white'],
                                 'fontWeight': '500'
                             }),
                dbc.CardBody([
                    dbc.Row([
                        dbc.Col([
                            html.Div([
                                html.Div("Bytes Sent", 
                                        style={
                                            'color': color_palette['raisin_black'],
                                            'fontSize': '0.9rem',
                                            'fontWeight': '500'
                                        }),
                                html.Div(id='bytes-sent', children="0", 
                                        style={
                                            'color': color_palette['delft_blue'],
                                            'fontSize': '1.5rem',
                                            'fontWeight': '600',
                                            'margin': '0.5rem 0 1rem 0'
                                        })
                            ], style={'textAlign': 'center'})
                        ]),
                        dbc.Col([
                            html.Div([
                                html.Div("Bytes Received", 
                                        style={
                                            'color': color_palette['raisin_black'],
                                            'fontSize': '0.9rem',
                                            'fontWeight': '500'
                                        }),
                                html.Div(id='bytes-received', children="0", 
                                        style={
                                            'color': color_palette['ucla_blue'],
                                            'fontSize': '1.5rem',
                                            'fontWeight': '600',
                                            'margin': '0.5rem 0 1rem 0'
                                        })
                            ], style={'textAlign': 'center'})
                        ])
                    ]),
                    dbc.Row([
                        dbc.Col([
                            html.Div([
                                html.Div("Packets Sent", 
                                        style={
                                            'color': color_palette['raisin_black'],
                                            'fontSize': '0.9rem',
                                            'fontWeight': '500'
                                        }),
                                html.Div(id='packets-sent', children="0", 
                                        style={
                                            'color': color_palette['powder_blue'],
                                            'fontSize': '1.5rem',
                                            'fontWeight': '600',
                                            'margin': '0.5rem 0 1rem 0'
                                        })
                            ], style={'textAlign': 'center'})
                        ]),
                        dbc.Col([
                            html.Div([
                                html.Div("Packets Received", 
                                        style={
                                            'color': color_palette['raisin_black'],
                                            'fontSize': '0.9rem',
                                            'fontWeight': '500'
                                        }),
                                html.Div(id='packets-received', children="0", 
                                        style={
                                            'color': color_palette['mint_green'],
                                            'fontSize': '1.5rem',
                                            'fontWeight': '600',
                                            'margin': '0.5rem 0 1rem 0'
                                        })
                            ], style={'textAlign': 'center'})
                        ])
                    ])
                ])
            ], className="shadow", style={
                'borderRadius': '8px',
                'border': 'none',
                'overflow': 'hidden'
            })
        ]),

        # # Button
        # dbc.Card([
        #     dbc.CardBody([
        #     html.Button("Reset Anomaly Buffer", id="reset-button", n_clicks=0, style={
        #     "padding": "10px",
        #     "backgroundColor": "#d9534f",
        #     "color": "white",
        #     "border": "none",
        #     "borderRadius": "5px",
        #     "width": "auto",
        #     "display": "block",
        #     "margin": "0 auto"
        #     }),
        #     html.Div(id="reset-status", style={
        #     "marginTop": "0.5rem", 
        #     "color": "green", 
        #     "textAlign": "center"
        #     })
        #     ])
        # ], className="shadow", style={
        #     'borderRadius': '8px',
        #     'border': 'none',
        #     'marginTop': '1.5rem',
        #     'overflow': 'hidden',
        #     'maxWidth': '300px',
        #     'position': 'absolute',  # Position the card absolutely
        #     'bottom': '10px',  # Adjust the distance from the bottom
        #     'left': '10px'  # Adjust the distance from the left
        # }),

        # Right column - Visualizations
        dbc.Col(md=8, children=[
            # Graph card
            dbc.Card([
                dbc.CardHeader("Traffic Metrics", 
                             style={
                                 'backgroundColor': color_palette['delft_blue'],
                                 'color': color_palette['white'],
                                 'fontWeight': '500'
                             }),
                dbc.CardBody([
                    dcc.Graph(id='live-graph', 
                             style={'height': '400px'}),
                    dcc.Interval(id='interval-component', 
                               interval=1000, 
                               n_intervals=0)
                ])
            ], className="shadow", style={
                'borderRadius': '8px',
                'border': 'none',
                'marginBottom': '1.5rem',
                'height': '500px',
                'overflow': 'hidden'
            }),
            
            # Flow predictions card
            dbc.Card([
                dbc.CardHeader("Flow Predictions", 
                             style={
                                 'backgroundColor': color_palette['ucla_blue'],
                                 'color': color_palette['white'],
                                 'fontWeight': '500'
                             }),
                dbc.CardBody([
                    html.Div(id="flow-table", 
                            style={
                                'height': '300px', 
                                'overflowY': 'auto',
                                'borderRadius': '4px',
                                'border': f"1px solid {color_palette['powder_blue']}"
                            }),
                    dcc.Interval(id="flow-refresh", 
                               interval=2000, 
                               n_intervals=0)
                ])
            ], className="shadow", style={
                'borderRadius': '8px',
                'border': 'none',
                'overflow': 'hidden'
            })
        ])
    ]),

    
    
    # Footer
    dbc.Row([
        dbc.Col([
            html.Div([
                html.P(f"© {datetime.now().year} SDN Monitoring System", 
                      style={
                          'color': color_palette['ucla_blue'],
                          'textAlign': 'center',
                          'fontSize': '0.8rem',
                          'marginTop': '2rem'
                      })
            ])
        ])
    ])
])

# Update graph callback with new color scheme
@app.callback(
    Output('live-graph', 'figure'),
    [Input('interval-component', 'n_intervals'),
     Input('device-id', 'value'),
     Input('port-id', 'value')]
)
def update_graph(n, device_id, port):
    global df

    if not device_id or not port:
        return {
            'layout': {
                'plot_bgcolor': 'rgba(0,0,0,0)',
                'paper_bgcolor': 'rgba(0,0,0,0)',
                'xaxis': {'visible': False},
                'yaxis': {'visible': False},
                'annotations': [{
                    'text': 'Please select Device ID and Port',
                    'xref': 'paper',
                    'yref': 'paper',
                    'showarrow': False,
                    'font': {
                        'size': 16, 
                        'color': color_palette['delft_blue']
                    }
                }]
            }
        }

    traffic = get_traffic(device_id, port)
    new_data = pd.DataFrame({
        'Time': [n],
        'bytesSent': [traffic["bytesSent"]],
        'bytesReceived': [traffic["bytesReceived"]],
        'packetsSent': [traffic["packetsSent"]],
        'packetsReceived': [traffic["packetsReceived"]],
        'timestamp': [traffic["timestamp"]]
    })
    df = pd.concat([df, new_data]).tail(30)

    fig = px.line(df, x='timestamp', y=['bytesSent', 'bytesReceived', 'packetsSent', 'packetsReceived'],
                 labels={'value': 'Traffic', 'variable': 'Metric'},
                 color_discrete_sequence=[
                     color_palette['delft_blue'],  # bytesSent
                     color_palette['ucla_blue'],   # bytesReceived
                     color_palette['powder_blue'],  # packetsSent
                     color_palette['mint_green']   # packetsReceived
                 ])
    
    fig.update_layout(
        title={
            'text': f"Traffic on {device_id} - Port {port}",
            'x': 0.5,
            'xanchor': 'center',
            'font': {'color': color_palette['raisin_black']}
        },
        plot_bgcolor=color_palette['white'],
        paper_bgcolor=color_palette['white'],
        hovermode='x unified',
        legend={
            'orientation': 'h',
            'yanchor': 'bottom',
            'y': 1.02,
            'xanchor': 'right',
            'x': 1,
            'font': {'color': color_palette['raisin_black']}
        },
        margin={'l': 40, 'r': 20, 't': 60, 'b': 40},
        xaxis={
            'gridcolor': color_palette['powder_blue'],
            'title': {'text': 'Time', 'font': {'color': color_palette['raisin_black']}},
            'tickfont': {'color': color_palette['ucla_blue']}
        },
        yaxis={
            'gridcolor': color_palette['powder_blue'],
            'title': {'text': 'Count', 'font': {'color': color_palette['raisin_black']}},
            'tickfont': {'color': color_palette['ucla_blue']}
        }
    )
    
    fig.update_traces(line={'width': 2.5})
    
    return fig

@app.callback(
    Output('port-id', 'options'),
    Input('device-id', 'value')
)
def update_ports(device_id):
    if not device_id:
        return []
    ports = get_ports(device_id)
    return [{'label': str(p), 'value': str(p)} for p in ports]

@app.callback(
    [Output('bytes-sent', 'children'),
     Output('bytes-received', 'children'),
     Output('packets-sent', 'children'),
     Output('packets-received', 'children')],
    [Input('interval-component', 'n_intervals'),
     Input('device-id', 'value'),
     Input('port-id', 'value')]
)
def update_metrics(n, device_id, port):
    if not device_id or not port:
        return ["0", "0", "0", "0"]
    
    traffic = get_traffic(device_id, port)
    return [
        f"{traffic['bytesSent']:,}",
        f"{traffic['bytesReceived']:,}",
        f"{traffic['packetsSent']:,}",
        f"{traffic['packetsReceived']:,}"
    ]


@app.callback(
    Output("flow-table", "children"),
    Input("flow-refresh", "n_intervals")
)
def update_flow_table(n):
    try:
        response = requests.get("http://localhost:8000/anomalies")
        if response.status_code == 200:
            data = response.json()
            recent_anomalies = data.get("recent", [])
            last_mitigated = data.get("last_mitigated", {})

            if not recent_anomalies:
                return html.Div([
                    html.P("No anomaly detected.", style={"textAlign": "center", "color": "gray"}),
                    html.P(f"Last Mitigated: {last_mitigated}", style={"textAlign": "center", "color": "gray", "fontSize": "12px"})
                ])

            df = pd.DataFrame(recent_anomalies)

            return html.Div([
                html.P(
                    f"Last Mitigated: ",
                    # {json.dumps(last_mitigated, indent=2)}
                    style={"whiteSpace": "pre-wrap", "fontSize": "12px", "color": "gray"}
                ),
                dash_table.DataTable(
                    columns=[{"name": i, "id": i} for i in df.columns],
                    data=df.to_dict("records"),
                    style_table={"overflowX": "auto"},
                    style_cell={"textAlign": "center", "fontSize": "12px"},
                    style_header={
                        "backgroundColor": color_palette["powder_blue"],
                        "fontWeight": "bold"
                    },
                    page_size=10
                )
            ])
        else:
            return html.P("Failed to fetch anomalies.", style={"textAlign": "center", "color": "red"})
    except Exception as e:
        return html.P(f"Error: {str(e)}", style={"textAlign": "center", "color": "red"})

# @app.callback(
#     Output("reset-status", "children"),
#     Input("reset-button", "n_clicks")
# )
# def reset_system(n_clicks):
#     if n_clicks < 1:
#         return ""

#     try:
#         # Reset anomaly buffer & reset_id di FastAPI
#         api_reset = requests.post("http://localhost:8000/reset")

#         # Reset flow buffer lokal dashboard (opsional)
#         flow_buffer.clear()

#         # Reset flow session (CICFlowMeter)
#         fs_reset = requests.post("http://localhost:5050/reset")

#         if api_reset.status_code == 200 and fs_reset.status_code == 200:
#             return "✅ Reset berhasil: Anomali & Flow Aktif dibersihkan."
#         else:
#             return f"⚠️ Reset gagal. API status: {api_reset.status_code}, FlowSession: {fs_reset.status_code}"
#     except Exception as e:
#         return f"❌ Error saat reset: {str(e)}"



# Keep all other callbacks the same as in previous versions
# [Previous callbacks for update_ports, update_metrics, update_flow_table remain unchanged]

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8050)
